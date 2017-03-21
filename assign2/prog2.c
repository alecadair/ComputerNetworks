#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* ******************************************************************
 ALTERNATING BIT AND GO-BACK-N NETWORK EMULATOR: VERSION 1.1  J.F.Kurose

     Network properties:
   - one way network delay averages five time units (longer if there
     are other messages in the channel for GBN), but can be larger
   - packets can be corrupted (either the header or the data portion)
     or lost, according to user-defined probabilities
   - packets will be delivered in the order in which they were sent
     (although some can be lost).
**********************************************************************/

#define BIDIRECTIONAL 0    /* change to 1 if you're doing extra credit */
                           /* and write a routine called B_output */

/* possible events: */
#define  TIMER_INTERRUPT 0
#define  FROM_LAYER5     1
#define  FROM_LAYER3     2
#define  OFF             0
#define  ON              1
#define   A    0
#define   B    1


int TRACE = 1;             /* for my debugging */
int nsim = 0;              /* number of messages from 5 to 4 so far */
int nsimmax = 0;           /* number of msgs to generate, then stop */
float time = 0.000;
float lossprob;            /* probability that a packet is dropped  */
float corruptprob;         /* probability that one bit is packet is flipped */
float lambda;              /* arrival rate of messages from layer 5 */
int   ntolayer3;           /* number sent into layer 3 */
int   nlost;               /* number lost in media */
int ncorrupt;              /* number corrupted by media */

/* a "msg" is the data unit passed from layer 5 (teachers code) to layer  */
/* 4 (students' code).  It contains the data (characters) to be delivered */
/* to layer 5 via the students transport level protocol entities.         */
struct msg {
  char data[20];
  };

/* a packet is the data unit passed from layer 4 (students code) to layer */
/* 3 (teachers code).  Note the pre-defined packet structure, which all   */
/* students must follow. */
struct pkt {
    int seqnum;
    int acknum;
    int checksum;
    char payload[20];
};
//time for timer to wait before timeout
int TIME_WAIT;
//counter for corrupted packets
float corrupted_packets = 0;
//counter for dropped packets
float dropped_packets = 0;
//counter for total packets sent to layer 3 from both sides
float packets_sent = 0;
//counter for ACKS
float ack_count = 0;
//counter for successful messages sent.
float sucessful_packets = 0;

//array to buffer packets into
struct pkt  pkt_buffer[1000];
//mark end of packets buffered.
int end_of_buff = 0;
//mark end of last packet ACKed.
int ack_index = 0;
//mark the first msg sent for A_output
int first_msg_sent = 0;

//variables to keep track of last ack and packets sent
struct pkt last_packet_sent;
struct pkt last_ack_pkt_sent;

//current sequence number sender is using
int seq_num = 0;
//current sequence number receiver is waiting to ack
int rcv_seq_num = 0;
//current ack the sender is waiting on
int ack_wait = 0;

char packets_are_equal(struct pkt, struct pkt);
void tolayer3(int,struct pkt);
void tolayer5(int,char[20]);
void starttimer(int,float);
void stoptimer(int);
char corrupt(struct pkt);
struct pkt checksum_pkt; void create_checksum(struct pkt* checksum_pkt);
char isACK(struct pkt, int);
void init();
void generate_next_arrival();
struct event p; void insertevent(struct event*p);
void printevlist();

/*returns 1 if all fields in pkt1 and pkt2 are equal to eachother*/
char packets_are_equal(struct pkt pkt1, struct pkt pkt2){
    for(int i =0; i < 20; i ++){
        if(pkt1.payload[i] != pkt2.payload[i])
            return 0;
    }
    if(pkt1.acknum != pkt2.acknum)
        return 0;
    if(pkt1.seqnum != pkt2.seqnum)
        return 0;
    return 1;
}
/*insert packet into queue for sending*/
void insert_packet_to_queue(struct pkt pkt_to_queue){
    pkt_buffer[end_of_buff] = pkt_to_queue;
    end_of_buff++;
}

/*returns 1 of packet is corrupt 0 otherwise*/
char corrupt(struct pkt packet){
    int check = 0;
    for(int i = 0; i < 20; i ++)
        check += packet.payload[i];
    check += packet.acknum;
    check += packet.seqnum;
    check += packet.checksum;
    check = ~check;
    if(check == 0)
        return 0;
    else
        return 1;
}
/*sets checksum of checksum_pkt*/
void create_checksum(struct pkt* checksum_pkt){
    int checksum = 0;
    //sum payload
    char * payload_ptr = checksum_pkt->payload;
    for(unsigned long i = 0; i < 20; i ++){
        char* temp = payload_ptr + i;
        checksum += (int)*(temp);
    }
    checksum += checksum_pkt->seqnum;
    checksum += checksum_pkt->acknum;
    checksum = ~checksum;
    checksum_pkt->checksum = checksum;
    return;
}

/*check if packet isn ACK packet with ack number to_check*/
char isACK(struct pkt packet, int to_check){
	char result;
	return result;
}

/********* STUDENTS WRITE THE NEXT SEVEN ROUTINES *********/
struct pkt make_packet(struct msg message, int ack, int seq){
    struct pkt new_packet;
    for(int i =0; i < 20; i++)
        new_packet.payload[i] = message.data[i];
    new_packet.acknum = ack;
    new_packet.seqnum = seq;
    create_checksum(&new_packet);
    return new_packet;
}

/* called from layer 5, passed the data to be sent to other side */
void A_output(struct msg message)
{
    char out_msg[20];
    for(int i = 0; i < 20; i ++)
        out_msg[i] = message.data[i];
    printf("Queuing message: %s to output buffer\n", out_msg);
    struct pkt packet_to_send = make_packet(message,0,seq_num);
    seq_num = !seq_num;
    printf("Sequence number for message: %d\n",!seq_num);
    printf("Checksum for packet is %04x\n\n", packet_to_send.checksum);
    insert_packet_to_queue(packet_to_send);
    if(!first_msg_sent){
        last_packet_sent = packet_to_send;
        tolayer3(A,packet_to_send);
        packets_sent ++;
        starttimer(A,TIME_WAIT);
        first_msg_sent = 1;
    }
}

void B_output(struct msg message)  /* need be completed only for extra credit */
{

}

/* called from layer 3, when a packet arrives for layer 4 */
void A_input(struct pkt packet)
{
    if(corrupt(packet)){
        printf("ACK packet corrupted\n");
        corrupted_packets ++;
        return;
    }if(packet.acknum != ack_wait){
        printf("ACK received for wrong packet.\n");
        dropped_packets ++;
        return;
    }
    ack_count++;
    printf("Packet correctly acknowledged.\n");
    printf("Packet ACK num: %d\n\n", packet.acknum);
    printf("Number of successfully ACKed packets: %d", ack_count);
    stoptimer(A);
    starttimer(A,TIME_WAIT);
    ack_index ++;
    sucessful_packets ++;
    ack_wait = !ack_wait;
    struct pkt pkt_to_send_B = pkt_buffer[ack_index];
    printf("Attempting to send new packet.\n");
    printf("Packet seq num: %d\n", pkt_to_send_B.seqnum);
    char output[20];
    for(int i = 0; i < 20; i ++)
        output[i] = pkt_to_send_B.payload[i];
    output[19] = '\0';
    printf("Packet message: %s\n\n", output);
    tolayer3(A,pkt_to_send_B);
    packets_sent ++;

}

/* called when A's timer goes off */
void A_timerinterrupt()
{
    printf("Timer hit packet being recent\n");
    printf("Sequence Number: %d\n", pkt_buffer[ack_index].seqnum);
    char pay[20];
    for(int i = 0; i < 20; i ++)
        pay[i] = pkt_buffer[ack_index].payload[i];
    pay[19] = '\0';
    printf("Payload being resent: %s\n\n", pay);
    tolayer3(A,pkt_buffer[ack_index]);
    packets_sent ++;
    starttimer(A,TIME_WAIT);

}  

/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init()
{
	memset(last_packet_sent.payload,0,20);
	last_packet_sent.acknum = 0;
    last_packet_sent.checksum = 0;
    last_packet_sent.checksum = 0;
    last_packet_sent.seqnum = 0;
    TIME_WAIT = 3*lambda;
}


/* Note that with simplex transfer from a-to-B, there is no B_output() */

/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet)
{

    char is_corrupt = corrupt(packet);
    if(is_corrupt){
        corrupted_packets ++;
        printf("Packet received at receiver corrupted\n\n");
        return;
    }
    if(packet.seqnum != rcv_seq_num){//packet retransmitted from A, corrupt ACK
        printf("Duplicate message received\n\n");
        struct msg structmsg;
        memset(structmsg.data, '0',20);
        struct pkt dup_ack_pkt = make_packet(structmsg, packet.seqnum, 0);
        tolayer3(B,dup_ack_pkt);
        return;
    }
    char new_msg[20];
    char new_msg_show[21];
    for(int i = 0; i < 20; i ++){
        new_msg[i] = packet.payload[i];
        new_msg_show[i] = packet.payload[i];
    }
    new_msg_show[20] = '\0';
    printf("Message successfully received at sender\n");
    printf("Message sequence number: %d\n", packet.seqnum);
    printf("Message %s\n\n", new_msg_show);
    tolayer5(B,new_msg);
    struct pkt ack_pkt;
    ack_pkt.acknum = rcv_seq_num;
    rcv_seq_num = !rcv_seq_num;
    memset(ack_pkt.payload,'0',20);
    ack_pkt.seqnum = 0;
    create_checksum(&ack_pkt);
    last_ack_pkt_sent = ack_pkt;
    tolayer3(B,ack_pkt);
    packets_sent ++;
}

/* called when B's timer goes off */
void B_timerinterrupt()
{
    //tolayer3(B, last_ack_pkt_sent);
    //starttimer(B,25);
}

/* the following rouytine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init()
{
}


/*****************************************************************
***************** NETWORK EMULATION CODE STARTS BELOW ***********
The code below emulates the layer 3 and below network environment:
  - emulates the tranmission and delivery (possibly with bit-level corruption
    and packet loss) of packets across the layer 3/4 interface
b b  - handles the starting/stopping of a timer, and generates timer
    interrupts (resulting in calling students timer handler).
  - generates message to be sent (passed from later 5 to 4)

THERE IS NOT REASON THAT ANY STUDENT SHOULD HAVE TO READ OR UNDERSTAND
THE CODE BELOW.  YOU SHOLD NOT TOUCH, OR REFERENCE (in your code) ANY
OF THE DATA STRUCTURES BELOW.  If you're interested in how I designed
the emulator, you're welcome to look at the code - but again, you should have
to, and you defeinitely should not have to modify
******************************************************************/

struct event {
   float evtime;           /* event time */
   int evtype;             /* event type code */
   int eventity;           /* entity where event occurs */
   struct pkt *pktptr;     /* ptr to packet (if any) assoc w/ this event */
   struct event *prev;
   struct event *next;
 };
struct event *evlist = NULL;   /* the event list */

int main()
{
   struct event *eventptr;
   struct msg  msg2give;
   struct pkt  pkt2give;
   
   int i,j;
   char c; 
  
   init();
   A_init();
   B_init();
   
   while (1) {
        eventptr = evlist;            /* get next event to simulate */
        if (eventptr==NULL)
           goto terminate;
        evlist = evlist->next;        /* remove this event[<64;62;42M] from event list */
        if (evlist!=NULL)
           evlist->prev=NULL;
        if (TRACE>=2) {
           printf("\nEVENT time: %f,",eventptr->evtime);
           printf("  type: %d",eventptr->evtype);
           if (eventptr->evtype==0)
	       printf(", timerinterrupt  ");
             else if (eventptr->evtype==1)
               printf(", fromlayer5 ");
             else
	     printf(", fromlayer3 ");
           printf(" entity: %d\n",eventptr->eventity);
           }
        time = eventptr->evtime;        /* update time to next event time */
        if (nsim==nsimmax)
	  break;                        /* all done with simulation */
        if (eventptr->evtype == FROM_LAYER5 ) {
            generate_next_arrival();   /* set up future arrival */
            /* fill in msg to give with string of same letter */    
            j = nsim % 26; 
            for (i=0; i<20; i++)  
               msg2give.data[i] = 97 + j;
            if (TRACE>2) {
               printf("          MAINLOOP: data given to student: ");
                 for (i=0; i<20; i++) 
                  printf("%c", msg2give.data[i]);
               printf("\n");
            }
            nsim++;
            if (eventptr->eventity == A) 
               A_output(msg2give);  
             else
               B_output(msg2give);  
            }
          else if (eventptr->evtype ==  FROM_LAYER3) {
            pkt2give.seqnum = eventptr->pktptr->seqnum;
            pkt2give.acknum = eventptr->pktptr->acknum;
            pkt2give.checksum = eventptr->pktptr->checksum;
            for (i=0; i<20; i++)  
                pkt2give.payload[i] = eventptr->pktptr->payload[i];
	    if (eventptr->eventity ==A)      /* deliver packet by calling */
   	       A_input(pkt2give);            /* appropriate entity */
            else
   	       B_input(pkt2give);
	    free(eventptr->pktptr);          /* free the memory for packet */
            }
          else if (eventptr->evtype ==  TIMER_INTERRUPT) {
            if (eventptr->eventity == A) 
	       A_timerinterrupt();
             else
	       B_timerinterrupt();
             }
          else  {
	     printf("INTERNAL PANIC: unknown event type \n");
             }
        free(eventptr);
        }

terminate:
   printf(" Simulator terminated at time %f\n after sending %d msgs from layer5\n",time,nsim);
}



void init()                         /* initialize the simulator */
{
  int i;
  float sum, avg;
  float jimsrand();
  
  
   printf("-----  Stop and Wait Network Simulator Version 1.1 -------- \n\n");
   printf("Enter the number of messages to simulate: ");
   scanf("%d",&nsimmax);
   printf("Enter  packet loss probability [enter 0.0 for no loss]:");
   scanf("%f",&lossprob);
   printf("Enter packet corruption probability [0.0 for no corruption]:");
   scanf("%f",&corruptprob);
   printf("Enter average time between messages from sender's layer5 [ > 0.0]:");
   scanf("%f",&lambda);
   printf("Enter TRACE:");
   scanf("%d",&TRACE);

   srand(9999);              /* init random number generator */
   sum = 0.0;                /* test random number generator for students */
   for (i=0; i<1000; i++)
      sum=sum+jimsrand();    /* jimsrand() should be uniform in [0,1] */
   avg = sum/1000.0;
   if (avg < 0.25 || avg > 0.75) {
    printf("It is likely that random number generation on your machine\n" ); 
    printf("is different from what this emulator expects.  Please take\n");
    printf("a look at the routine jimsrand() in the emulator code. Sorry. \n");
    exit(-1);
    }

   ntolayer3 = 0;
   nlost = 0;
   ncorrupt = 0;

   time=0.0;                    /* initialize time to 0.0 */
   generate_next_arrival();     /* initialize event list */
}

/****************************************************************************/
/* jimsrand(): return a float in range [0,1].  The routine below is used to */
/* isolate all random number generation in one location.  We assume that the*/
/* system-supplied rand() function return an int in therange [0,mmm]        */
/****************************************************************************/
float jimsrand() 
{
  double mmm = 2147483647;   /* largest int  - MACHINE DEPENDENT!!!!!!!!   */
  float x;                   /* individual students may need to change mmm */ 
  x = rand()/mmm;            /* x should be uniform in [0,1] */
  return(x);
}  

/********************* EVENT HANDLINE ROUTINES *******/
/*  The next set of routines handle the event list   */
/*****************************************************/
 
void generate_next_arrival()
{
   double x,log(),ceil();
   struct event *evptr;
   //    char *malloc();
   float ttime;
   int tempint;

   if (TRACE>2)
       printf("          GENERATE NEXT ARRIVAL: creating new arrival\n");
 
   x = lambda*jimsrand()*2;  /* x is uniform on [0,2*lambda] */
                             /* having mean of lambda        */
   evptr = (struct event *)malloc(sizeof(struct event));
   evptr->evtime =  time + x;
   evptr->evtype =  FROM_LAYER5;
   if (BIDIRECTIONAL && (jimsrand()>0.5) )
      evptr->eventity = B;
    else
      evptr->eventity = A;
   insertevent(evptr);
} 


void insertevent(struct event *p)
{
   struct event *q,*qold;

   if (TRACE>2) {
      printf("            INSERTEVENT: time is %lf\n",time);
      printf("            INSERTEVENT: future time will be %lf\n",p->evtime); 
      }
   q = evlist;     /* q points to header of list in which p struct inserted */
   if (q==NULL) {   /* list is empty */
        evlist=p;
        p->next=NULL;
        p->prev=NULL;
        }
     else {
        for (qold = q; q !=NULL && p->evtime > q->evtime; q=q->next)
              qold=q; 
        if (q==NULL) {   /* end of list */
             qold->next = p;
             p->prev = qold;
             p->next = NULL;
             }
           else if (q==evlist) { /* front of list */
             p->next=evlist;
             p->prev=NULL;
             p->next->prev=p;
             evlist = p;
             }
           else {     /* middle of list */
             p->next=q;
             p->prev=q->prev;
             q->prev->next=p;
             q->prev=p;
             }
         }
}

void printevlist()
{
  struct event *q;
  int i;
  printf("--------------\nEvent List Follows:\n");
  for(q = evlist; q!=NULL; q=q->next) {
    printf("Event time: %f, type: %d entity: %d\n",q->evtime,q->evtype,q->eventity);
    }
  printf("--------------\n");
}



/********************** Student-callable ROUTINES ***********************/

/* called by students routine to cancel a previously-started timer */
void stoptimer(int AorB)  /* A or B is trying to stop timer */
{
 struct event *q,*qold;

 if (TRACE>2)
    printf("          STOP TIMER: stopping timer at %f\n",time);
/* for (q=evlist; q!=NULL && q->next!=NULL; q = q->next)  */
 for (q=evlist; q!=NULL ; q = q->next) 
    if ( (q->evtype==TIMER_INTERRUPT  && q->eventity==AorB) ) { 
       /* remove this event */
       if (q->next==NULL && q->prev==NULL)
             evlist=NULL;         /* remove first and only event on list */
          else if (q->next==NULL) /* end of list - there is one in front */
             q->prev->next = NULL;
          else if (q==evlist) { /* front of list - there must be event after */
             q->next->prev=NULL;
             evlist = q->next;
             }
           else {     /* middle of list */
             q->next->prev = q->prev;
             q->prev->next =  q->next;
             }
       free(q);
       return;
     }
  printf("Warning: unable to cancel your timer. It wasn't running.\n");
}


void starttimer(int AorB,float increment)
{

 struct event *q;
 struct event *evptr;
 //char *malloc();

 if (TRACE>2)
    printf("          START TIMER: starting timer at %f\n",time);
 /* be nice: check to see if timer is already started, if so, then  warn */
/* for (q=evlist; q!=NULL && q->next!=NULL; q = q->next)  */
   for (q=evlist; q!=NULL ; q = q->next)  
    if ( (q->evtype==TIMER_INTERRUPT  && q->eventity==AorB) ) { 
      printf("Warning: attempt to start a timer that is already started\n");
      return;
      }
 
/* create future event for when timer goes off */
   evptr = (struct event *)malloc(sizeof(struct event));
   evptr->evtime =  time + increment;
   evptr->evtype =  TIMER_INTERRUPT;
   evptr->eventity = AorB;
   insertevent(evptr);
} 


/************************** TOLAYER3 ***************/
void tolayer3(AorB,packet)
int AorB;  /* A or B is trying to stop timer */
struct pkt packet;
{
 struct pkt *mypktptr;
 struct event *evptr,*q;
 //char *malloc();
 float lastime, x, jimsrand();
 int i;


 ntolayer3++;

 /* simulate losses: */
 if (jimsrand() < lossprob)  {
      nlost++;
      if (TRACE>0)    
	printf("          TOLAYER3: packet being lost\n");
      return;
    }  

/* make a copy of the packet student just gave me since he/she may decide */
/* to do something with the packet after we return back to him/her */ 
 mypktptr = (struct pkt *)malloc(sizeof(struct pkt));
 mypktptr->seqnum = packet.seqnum;
 mypktptr->acknum = packet.acknum;
 mypktptr->checksum = packet.checksum;
 for (i=0; i<20; i++)
    mypktptr->payload[i] = packet.payload[i];
 if (TRACE>2)  {
   printf("          TOLAYER3: seq: %d, ack %d, check: %d ", mypktptr->seqnum,
	  mypktptr->acknum,  mypktptr->checksum);
    for (i=0; i<20; i++)
        printf("%c",mypktptr->payload[i]);
    printf("\n");
   }

/* create future event for arrival of packet at the other side */
  evptr = (struct event *)malloc(sizeof(struct event));
  evptr->evtype =  FROM_LAYER3;   /* packet will pop out from layer3 */
  evptr->eventity = (AorB+1) % 2; /* event occurs at other entity */
  evptr->pktptr = mypktptr;       /* save ptr to my copy of packet */
/* finally, compute the arrival time of packet at the other end.
   medium can not reorder, so make sure packet arrives between 1 and 10
   time units after the latest arrival time of packets
   currently in the medium on their way to the destination */
 lastime = time;
/* for (q=evlist; q!=NULL && q->next!=NULL; q = q->next) */
 for (q=evlist; q!=NULL ; q = q->next) 
    if ( (q->evtype==FROM_LAYER3  && q->eventity==evptr->eventity) ) 
      lastime = q->evtime;
 evptr->evtime =  lastime + 1 + 9*jimsrand();
 


 /* simulate corruption: */
 if (jimsrand() < corruptprob)  {
    ncorrupt++;
    if ( (x = jimsrand()) < .75)
       mypktptr->payload[0]='Z';   /* corrupt payload */
      else if (x < .875)
       mypktptr->seqnum = 999999;
      else
       mypktptr->acknum = 999999;
    if (TRACE>0)    
	printf("          TOLAYER3: packet being corrupted\n");
    }  

  if (TRACE>2)  
     printf("          TOLAYER3: scheduling arrival on other side\n");
  insertevent(evptr);
} 

void tolayer5(AorB,datasent)
  int AorB;
  char datasent[20];
{
  int i;  
  if (TRACE>2) {
      printf("%s          TOLAYER5: data received: ","\x1B[31m");
      printf("%s","\x1B[0m");
     for (i=0; i<20; i++)  
        printf("%c",datasent[i]);
     printf("\n");
   }
  
}
