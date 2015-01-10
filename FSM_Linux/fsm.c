//
// fsm.c
// FSM sample code
//
// Created by Minsuk Lee, 2014.11.1.
// Copyright (c) 2014. Minsuk Lee All rights reserved.
// see LICENSE

#include "util.h"

#define CONNECT_TIMEOUT 2
#define CONNECT_TRY 10

#define NUM_STATE   4
#define NUM_EVENT   9

enum pakcet_type { F_CON = 0, F_FIN = 1, F_ACK = 2, F_DATA = 3 };   // Packet Type
enum proto_state { wait_CON = 0, CON_sent = 1, CONNECTED = 2, wait_ACK = 3 };     // States

// Events
enum proto_event { RCV_CON = 0, RCV_FIN = 1, RCV_ACK = 2, RCV_DATA = 3,
                   CONNECT = 4, CLOSE = 5,   SEND = 6,    TIMEOUT = 7,  TIMEOUT_3 = 8 };

char *pkt_name[] = { "F_CON", "F_FIN", "F_ACK", "F_DATA" };
char *st_name[] =  { "wait_CON", "CON_sent", "CONNECTED", "wait_ACK" };
char *ev_name[] =  { "RCV_CON", "RCV_FIN", "RCV_ACK", "RCV_DATA",
                     "CONNECT", "CLOSE",   "SEND",    "TIMEOUT",    "TIMEOUT_3"};

struct state_action {           // Protocol FSM Structure
    void (* action)(void *p);
    enum proto_state next_state;
};

#define MAX_DATA_SIZE   (500)
struct packet {                 // 504 Byte Packet to & from Simulator
    unsigned short type;        // enum packet_type
    unsigned short size;
    char data[MAX_DATA_SIZE];
};

// struct packet pkt;

struct p_event {                // Event Structure
    enum proto_event event;
    struct packet packet;
    struct packet snd_packet;
    int size;
};

enum proto_state c_state = wait_CON;         // Initial State
volatile int timedout	 = 0;

static void timer_handler(int signum)
{
    printf("Timedout\n");
    timedout = 1;
}

static void timer_init(void)
{
    struct sigaction sa;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = &timer_handler;
    sigaction(SIGALRM, &sa, NULL);
}

void set_timer(int sec)
{
    struct itimerval timer;

    timedout = 0;
    timer.it_value.tv_sec = sec;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;   // Non Periodic timer
    timer.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &timer, NULL);
}

int data_count = 0;
int timeout_count = 1;

void send_packet(int flag, void *p, int size)
{
    struct packet pkt;
    printf("SEND %s\n", pkt_name[flag]);
    
    pkt.type = flag;
    pkt.size = size;
    if (size)
        memcpy(pkt.data, ((struct p_event *)p)->snd_packet.data, (size > MAX_DATA_SIZE) ? MAX_DATA_SIZE : size);
    Send((char *)&pkt, sizeof(struct packet) - MAX_DATA_SIZE + size);
}

static void snd_con() {
    send_packet(F_CON, NULL, 0);
}

static void snd_ack() {
    send_packet(F_ACK, NULL, 0);
}

static void snd_data(void *p) {
    send_packet(F_DATA, (struct p_event *)p, ((struct p_event *)p)->size);
}

static void snd_fin() {
    send_packet(F_FIN, NULL, 0);
}

static void strt_timer() {
    set_timer(CONNECT_TIMEOUT);
}

static void stp_timer() {
    set_timer(0);
}

static void init_counter() {
    timeout_count = 1;
}

static void report_connect(void *p) {
    stp_timer();
    init_counter();
    
//    set_timer(0);
//    timeout_count = 1;
    printf("Connected\n");
}

static void send_ack(void *p) {
    snd_ack();
//    send_packet(F_ACK, NULL, 0);
}

static void passive_con(void *p) {
    snd_ack();
//    send_packet(F_ACK, NULL, 0);
    report_connect(NULL);
}

static void active_con(void *p) {
    snd_con();
//    send_packet(F_CON, NULL, 0);
    set_timer(CONNECT_TIMEOUT);
}

static void close_con(void *p) {
    snd_fin();
//    send_packet(F_FIN, NULL, 0);
    printf("Connection Closed\n");
}

static void send_data(void *p) {
    snd_data(p);
//    send_packet(F_DATA, (struct p_event *)p, ((struct p_event *)p)->size);
    set_timer(CONNECT_TIMEOUT);
    printf("Send Data to peer '%s' size:%d\n",
           ((struct p_event*)p)->snd_packet.data, ((struct p_event*)p)->size);
}

static void report_data(void *p) {
    snd_ack();
//    send_packet(F_ACK, NULL, 0);
    printf("Data Arrived data='%s' size:%d\n",
           ((struct p_event*)p)->packet.data, ((struct p_event*)p)->packet.size);
}

static void report_ack(void *p) {
    stp_timer();
    init_counter();
    
//    set_timer(0);
//    timeout_count = 1;
    printf("Peer got data '%s' \n",
           ((struct p_event*)p)->snd_packet.data);
}

struct state_action p_FSM[NUM_STATE][NUM_EVENT] = {
  //  for each event:
  //  RCV_CON,                 RCV_FIN,                 RCV_ACK,
  //  RCV_DATA,                CONNECT,                 CLOSE,
  //  SEND,                    TIMEOUT,                 TIMEOUT_3

  // - wait_CON state
  {{ passive_con, CONNECTED }, { NULL, wait_CON }, { NULL, wait_CON },
   { NULL, wait_CON }, { active_con,  CON_sent },  { NULL, wait_CON },
   { NULL, wait_CON }, { NULL, wait_CON },  { NULL, wait_CON }},

  // - CON_sent state
  {{ passive_con, CONNECTED }, { close_con, wait_CON }, { report_connect, CONNECTED },
   { NULL, CON_sent },  { active_con, CON_sent },  { close_con, wait_CON },
   { NULL, CON_sent },  { active_con, CON_sent },  { close_con, wait_CON }},

  // - CONNECTED state
  {{ send_ack, CONNECTED }, { close_con, wait_CON }, { NULL, CONNECTED },
   { report_data, CONNECTED }, { NULL, CONNECTED }, { close_con, wait_CON },
   { send_data, wait_ACK }, { NULL, CONNECTED }, { NULL, CONNECTED }},
    
  // - wait_ACK state
  {{ NULL, wait_ACK }, { close_con, wait_ACK }, { report_ack, CONNECTED },
   { report_data, wait_ACK }, { NULL, wait_ACK }, { close_con, wait_ACK },
   { NULL, wait_ACK }, { send_data, wait_ACK }, { close_con, wait_ACK }}
};

struct p_event *get_event(void)
{
    static struct p_event event;    // not thread-safe
    
loop:
    // Check if there is user command
    if (!kbhit()) {
        // Check if timer is timed-out
        if (timedout) {
            timedout = 0;
			printf("timeout_count: %d\n", timeout_count);
			if (timeout_count++ >= CONNECT_TRY) {
				event.event = TIMEOUT_3;
				timeout_count = 1;
            } else if (c_state == CON_sent || c_state == wait_ACK) {
                event.event = TIMEOUT;
                
                
            }
        } else {
            // Check Packet arrival by event_wait()
            ssize_t n = Recv((char*)&event.packet, sizeof(struct packet));
            if (n > 0) {
                // if then, decode header to make event
                switch (event.packet.type) {
                    case F_CON:  event.event = RCV_CON;  break;
                    case F_ACK:  event.event = RCV_ACK;  break;
                    case F_FIN:  event.event = RCV_FIN;  break;
                    case F_DATA:
                        event.event = RCV_DATA; break;
                        event.size = event.packet.size;
                        break;
                    default:
                        goto loop;
                }
            } else
                goto loop;
        }
    } else {
        int n = getchar();
        switch (n) {
            case '0': event.event = CONNECT; break;
            case '1': event.event = CLOSE;   break;
            case '2':
                if (c_state == CONNECTED) {
                    event.event = SEND;
                    sprintf(event.snd_packet.data, "%09d", data_count++);
                    event.size = strlen(event.snd_packet.data) + 1;
                } else
                    printf("Cannot send message now...\n");
                break;
            case '3': return NULL;  // QUIT
            default:
                goto loop;
        }
    }
    return &event;
}

void
Protocol_Loop(void)
{
    struct p_event *eventp;

    timer_init();
    while (1) {
        printf("Current State = %s\n", st_name[c_state]);

        /* Step 0: Get Input Event */
        if((eventp = get_event()) == NULL)
            break;
        printf("EVENT : %s\n",ev_name[eventp->event]);
        /* Step 1: Do Action */
        if (p_FSM[c_state][eventp->event].action)
            p_FSM[c_state][eventp->event].action(eventp);
        else
            printf("No Action for this event\n");

        /* Step 2: Set Next State */
        c_state = p_FSM[c_state][eventp->event].next_state;
    }
}

int
main(int argc, char *argv[])
{
    ChannelNumber channel;
    ID id;
    int rateOfPacketLoss;

    printf("Channel : ");
    scanf("%d",&channel);
    printf("ID : ");
    scanf("%d",&id);
    printf("Rate of Packet Loss (0 ~ 100)%% : ");
    scanf("%d",&rateOfPacketLoss);
    if (rateOfPacketLoss < 0)
        rateOfPacketLoss = 0;
    else if (rateOfPacketLoss > 100)
        rateOfPacketLoss = 100;
        
    // Login to SIMULATOR

    if (Login(channel, id, rateOfPacketLoss) == -1) {
        printf("Login Failed\n");
        return -1;
    }

    printf("Entering protocol loop...\n");
    printf("type number '[0]CONNECT', '[1]CLOSE', '[2]SEND', or '[3]QUIT'\n");
    Protocol_Loop();

    // SIMULATOR_CLOSE

    return 0;
}

