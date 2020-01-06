/* BGP packet management routine.
   Copyright (C) 1999 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "thread.h" 
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "sockunion.h"    /* for inet_ntop () */
#include "sockopt.h"
#include "linklist.h"
#include "plist.h"
#include "filter.h"
#include <stdbool.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_encap.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nht.h"

#include "bgpd/bgp_vty.h"
#include <stdio.h> 
#include <stdlib.h> 
/* we import CIRCA global variables */
extern struct peer *avatar;
extern int working_mode;
#define EVENT_ID_LENGTH  20
#define PREFIX_LENGTH  20
#define TIME_STAMP_LENGTH 20
#define ASPATH_SIZE 50
int stream_put_prefix (struct stream *, struct prefix *);

bool received_packet_is_withdraw=false;
/* ************ related functions to CIRCA implementation start here ******* */
extern prefix_list_head;
extern event_affected_prefix_list_head;
extern struct peer *a_peer_for_maintating_head_of_data_structure;
extern time_stamp_ds_head;
extern converged_head;
extern sent_head ;
extern cause_head ;
extern neighbours_sent_to_head;
extern caused_time_stamps_head;
extern peer_list_for_sending_head;
extern char * global_event_id[EVENT_ID_LENGTH];
extern long sequence_number_for_event_ids;
// A linked list node 
struct Node 
{ 
  int data; 
  struct Node *next; 
}; 
  
/* Given a reference (pointer to pointer) to the head of a list and  
   an int, inserts a new node on the front of the list. */
void push(struct Node** head_ref, int new_data) 
{ 
    /* 1. allocate node */
    struct Node* new_node = (struct Node*) malloc(sizeof(struct Node)); 
  
    /* 2. put in the data  */
    new_node->data  = new_data; 
  
    /* 3. Make next of new node as head */
    new_node->next = (*head_ref); 
  
    /* 4. move the head to point to the new node */
    (*head_ref)    = new_node; 
} 
  
/* Given a node prev_node, insert a new node after the given  
   prev_node */
void insertAfter(struct Node* prev_node, int new_data) 
{ 
    /*1. check if the given prev_node is NULL */
    if (prev_node == NULL) 
    { 
      printf("the given previous node cannot be NULL"); 
      return; 
    } 
  
    /* 2. allocate new node */
    struct Node* new_node =(struct Node*) malloc(sizeof(struct Node)); 
  
    /* 3. put in the data  */
    new_node->data  = new_data; 
  
    /* 4. Make next of new node as next of prev_node */
    new_node->next = prev_node->next; 
  
    /* 5. move the next of prev_node as new_node */
    prev_node->next = new_node; 
} 
  
/* Given a reference (pointer to pointer) to the head 
   of a list and an int, appends a new node at the end  */
void append(struct Node** head_ref, int new_data) 
{ 
    /* 1. allocate node */
    struct Node* new_node = (struct Node*) malloc(sizeof(struct Node)); 
  
    struct Node *last = *head_ref;  /* used in step 5*/
  
    /* 2. put in the data  */
    new_node->data  = new_data; 
  
    /* 3. This new node is going to be the last node, so make next of 
          it as NULL*/
    new_node->next = NULL; 
  
    /* 4. If the Linked List is empty, then make the new node as head */
    if (*head_ref == NULL) 
    { 
       *head_ref = new_node; 
       return; 
    } 
  
    /* 5. Else traverse till the last node */
    while (last->next != NULL) 
        last = last->next; 
  
    /* 6. Change the next of last node */
    last->next = new_node; 
    return; 
} 
  
// This function prints contents of linked list starting from head 
void printList(struct Node *node) 
{ 
  while (node != NULL) 
  { 
     //printf(" %d ", node->data); 
    zlog_debug ("here is the data of list %d",node->data);

     node = node->next; 
  } 
} 

/* 
 this function will make the link up between the neighbor which its AS number is equal to 
 passed target_router_id 
*/

void link_up_root_cause_event_handler(struct peer *peer, long target_router_id) 
{

/* here we will make the link up */
    zlog_debug ("here we will make the link up with %ld",target_router_id);
  struct peer *peer2;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  bgp = bgp_get_default ();
  if (! bgp)
    return 0;
  
  /* Upon receipt of an GRC link up message,: */


  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer->as == target_router_id)
          //bgp_timer_set (peer);
          peer_activate(peer,AFI_IP, SAFI_UNICAST);

    }

}

void link_down_root_cause_event_handler(struct peer *peer, long target_router_id) 
{

/* here we will make the link down by deactivating the peer by calling peer_deactivate function*/
  zlog_debug ("we are going to make the link down with %ld",target_router_id);
  struct peer *peer2;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  bgp = bgp_get_default ();
  if (! bgp)
    return 0;
  
  /* Upon receipt of an GRC link down message,: */

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer->as == target_router_id)
          //peer_delete (peer);
          //bgp_stop (peer);
          peer_deactivate(peer,AFI_IP, SAFI_UNICAST);


    }

    // for neighbor in neighbors:
    // if neighbor_id == target_id
    //  peer_deldete(neighbor);

}

/*
we first extract CIRCA sub type and then based on received sub type
 of root cause event, we will call root cause simulation, CDC first, second or third phase
*/
void CIRCA_GRC_messages_handler(struct peer *peer,int size)
{

long received_sub_type_code; 
  long received_seq_number;
  long received_seq_number2;
  long target_router_id; 

  u_char *end;
  struct stream *s;
  
  /* Status must be Established. */
  if (peer->status != Established) 
    {
      zlog_err ("%s [FSM] CIRCA packet received under status %s",
    peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }

  s = peer->ibuf;
  char result7[50]; 
  end = stream_pnt (s) + size;
  if (  size == 4 )
    {
    zlog_debug ("2 we have received a circa message but the lenght is 4 which is error");
      return -1;
    }

  /* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
     Length is too large (i.e., if Unfeasible Routes Length + Total
     Attribute Length + 23 exceeds the message Length), then the Error
     Subcode is set to Malformed Attribute List.  */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_err ("%s [Error] CIRCA packet error"
    " (packet length is short for unfeasible length)",
    peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }
    int size_of_stream = s->size;
    int end_of_s = s->endp;
  /* get root cause evnt id. */
  received_sub_type_code = stream_getl (s);
// zlog_debug ("this is received_sub_type_code %ld from %s",received_sub_type_code,peer->host);
  /* get sequence number . */
  received_seq_number = stream_getl (s);
// zlog_debug ("this is received_seq_number %ld ",received_seq_number);
  /* get second sequence number which only being used in CBGP messages not in GRC messages . */
  received_seq_number2 = stream_getl (s);
// zlog_debug ("this is received_seq_number2 %ld ",received_seq_number2);

  /* get rtarget router id whic is AS number in our implementation. this could be the name of target router

target router is the router which we need to simulate link up or link down with it. If for example, 
we have a link up in ground between B and A, and B's avatar is receiving GRC message, the target router will be A's avatar.
  */
  target_router_id = stream_getl (s);
// zlog_debug ("this is target_router_id %ld ",target_router_id);
  /* we will set the root cause event unique label to the global varaible */
  
  char * time_stamp_set_by_GRC_MSG[TIME_STAMP_LENGTH];
  //zlog_debug ("7 we have received a circa message but the lenght is 4 which is error %s",event_id_sent_by_ground);
  char * event_id_sent_by_ground[EVENT_ID_LENGTH];
  strncpy(event_id_sent_by_ground,"NULL",EVENT_ID_LENGTH);
  sprintf(event_id_sent_by_ground, "%u", received_seq_number);

  char * char_my_router_id[20];
  sprintf(char_my_router_id, "%u", peer->local_as);
  strcat(event_id_sent_by_ground, ",");
  strcat(event_id_sent_by_ground, char_my_router_id);
  // zlog_debug (" *********************** %s this is event_id ********* ", event_id_sent_by_ground);

  switch(received_sub_type_code)
  {
  case LINK_UP:// root cause event is link up
    zlog_debug (" %ld this is a link up GRC", received_sub_type_code);
    zlog_debug ("Cloud receiving GRC message type:LINK_UP target_router:%ld, from:%ld to: %ld",target_router_id,avatar->as,peer->local_as);
    link_up_root_cause_event_handler(peer,target_router_id);
  break;
  case LINK_DOWN: // root cause event is link down
    zlog_debug (" %ld this is a link down GRC", received_sub_type_code);
    zlog_debug ("Cloud receiving GRC message type:LINK_DOWN target_router:%ld, from:%ld to: %ld",target_router_id,avatar->as,peer->local_as);
    link_down_root_cause_event_handler(peer,target_router_id);
  break;
  case NEW_POLICY: // root cause event is link down
  break;
  case NEW_PREFIX: // root cause event is link down
  break;
  default:
  break;
}
}


/* ************** end of CIRCA related codes  ************** */



/* Set up BGP packet marker and packet type. */
static int
bgp_packet_set_marker (struct stream *s, u_char type)
{
  int i;

  /* Fill in marker. */
  for (i = 0; i < BGP_MARKER_SIZE; i++)
    stream_putc (s, 0xff);

  /* Dummy total length. This field is should be filled in later on. */
  stream_putw (s, 0);

  /* BGP packet type. */
  stream_putc (s, type);

  /* Return current stream size. */
  return stream_get_endp (s);
}

/* Set BGP packet header size entry.  If size is zero then use current
   stream size. */
static int
bgp_packet_set_size (struct stream *s)
{
  int cp;

  /* Preserve current pointer. */
  cp = stream_get_endp (s);
  stream_putw_at (s, BGP_MARKER_SIZE, cp);

  return cp;
}

/* Add new packet to the peer. */
static void
bgp_packet_add (struct peer *peer, struct stream *s)
{
  /* Add packet to the end of list. */
  stream_fifo_push (peer->obuf, s);
}

/* Free first packet. */
static void
bgp_packet_delete (struct peer *peer)
{
  stream_free (stream_fifo_pop (peer->obuf));
}

/* Check file descriptor whether connect is established. */
static void
bgp_connect_check (struct peer *peer)
{
  int status;
  socklen_t slen;
  int ret;

  /* Anyway I have to reset read and write thread. */
  BGP_READ_OFF (peer->t_read);
  BGP_WRITE_OFF (peer->t_write);

  /* Check file descriptor. */
  slen = sizeof (status);
  ret = getsockopt(peer->fd, SOL_SOCKET, SO_ERROR, (void *) &status, &slen);

  /* If getsockopt is fail, this is fatal error. */
  if (ret < 0)
    {
      zlog (peer->log, LOG_INFO, "can't get sockopt for nonblocking connect");
      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return;
    }      

  /* When status is 0 then TCP connection is established. */
  if (status == 0)
    {
      BGP_EVENT_ADD (peer, TCP_connection_open);
    }
  else
    {
      if (BGP_DEBUG (events, EVENTS))
    plog_debug (peer->log, "%s [Event] Connect failed (%s)",
         peer->host, safe_strerror (errno));
      BGP_EVENT_ADD (peer, TCP_connection_open_failed);
    }
}



/* Parse CIRCA FIB entry packet */
void
circa_fib_entry_list_of_prefixes_receive (struct peer *peer, bgp_size_t size)
{
  zlog_debug ("we received a circa fib entry message from %s",peer->host);
  long seq_number_part_of_event_id;
  long router_id_part_of_event_id;
  long seq_number_part_of_time_stamp;
  long router_id_part_of_time_stamp;
  long CIRCA_sub_type;
  long next_hop_AS_number ;

  int ret, nlri_ret;
  u_char *end;
  struct stream *s;
  struct attr attr;
  struct attr_extra extra;
  bgp_size_t attribute_len;
  bgp_size_t update_len;
  bgp_size_t withdraw_len;
  int i;
  
  enum NLRI_TYPES {
    NLRI_UPDATE,
    NLRI_WITHDRAW,
    NLRI_MP_UPDATE,
    NLRI_MP_WITHDRAW,
    NLRI_TYPE_MAX,
  };
  struct bgp_nlri nlris[NLRI_TYPE_MAX];

  /* Status must be Established. */
  if (peer->status != Established) 
    {
      zlog_err ("%s [FSM] Update packet received under status %s",
    peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }

  /* Set initial values. */
  memset (&attr, 0, sizeof (struct attr));
  memset (&extra, 0, sizeof (struct attr_extra));
  memset (&nlris, 0, sizeof nlris);

  attr.extra = &extra;

  s = peer->ibuf;
  end = stream_pnt (s) + size;

  /* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
     Length is too large (i.e., if Unfeasible Routes Length + Total
     Attribute Length + 23 exceeds the message Length), then the Error
     Subcode is set to Malformed Attribute List.  */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_err ("%s [Error] Update packet error"
    " (packet length is short for unfeasible length)",
    peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }
    /* get CIRCA related fields */
    CIRCA_sub_type = stream_getl (s);
    // zlog_debug ("this is CIRCA_sub_type %ld from %s",CIRCA_sub_type,peer->host);


    /* get event id sequence number section */
    seq_number_part_of_event_id = stream_getl (s);
    // zlog_debug ("this is seq_number_part_of_event_id %ld from %s",seq_number_part_of_event_id,peer->host);

    /* get event id router id section */
    router_id_part_of_event_id = stream_getl (s);
// zlog_debug ("this is router_id_part_of_event_id %ld from %s",router_id_part_of_event_id,peer->host);
  
  char * in_event_id[EVENT_ID_LENGTH];
  concat_long_values( seq_number_part_of_event_id,router_id_part_of_event_id ,&in_event_id,EVENT_ID_LENGTH);

  next_hop_AS_number = stream_getl (s);
  /* get prefix */



// /* get aspath */
//   struct bgp_attr_parser_args attr_args = {
//           .peer = peer,
//           .length = length,
//           .attr = attr,
//           .type = type,
//           .flags = flag,
//           .startp = startp,
//           .total = attr_endp - startp,
//         };

//   bgp_attr_parse_ret_t ret = bgp_attr_nexthop (&attr_args);

  zlog_debug ("Receiving FIB entries for RCE_ID: %s from:%ld to:%ld and next hop is %ld",in_event_id,peer->as,peer->local_as,next_hop_AS_number);
}

void circa_fib_dispatching(char * event_id)
{
  zlog_debug ("Sending FIB entries for RCE_ID: %s ",event_id);
    if (avatar)
  {
  // zlog_debug ("2 Sending FIB entries for RCE_ID: %s ",event_id);
  int number_of_affected_prefixes = 0;
  int AS_number_for_next_hop = get_next_hop_for_event(&time_stamp_ds_head,event_id);
  // zlog_debug ("3 Sending FIB entries for RCE_ID: %s ",event_id);
  number_of_affected_prefixes = get_number_of_got_affected_prefixes_by_event(&time_stamp_ds_head,event_id);
  zlog_debug ("Sending FIB entries for RCE_ID: %s and for %ld prefixes",event_id,number_of_affected_prefixes);
  struct event_affected_prefix_list * list_of_all_prefixes  ;
  list_of_all_prefixes = get_prefix_list_affected_by_event(&time_stamp_ds_head,event_id);
  struct  update_prefix_list * list_of_affected_prefixes_str_version;
  list_of_affected_prefixes_str_version = get_prefix_list_affected_by_event_str_variable(&time_stamp_ds_head,event_id);
  zlog_debug ("****  we got the prefix list calling get_prefix_list_affected_by_event for RCE_ID: %s",event_id);
  
  if(list_of_affected_prefixes_str_version !=NULL)
    zlog_debug ("****  The prefix list for RCE_ID: %s in str version is not null",event_id);

  if(list_of_affected_prefixes_str_version ==NULL)
    zlog_debug ("****  The prefix list for RCE_ID: %s in str version is null",event_id);
  if(list_of_all_prefixes ==NULL)
    zlog_debug ("****  The prefix list for RCE_ID: %s is null",event_id);
  else
    zlog_debug ("****  The prefix list for RCE_ID: %s is not null",event_id);

  //print_update_prefix_list(&list_of_all_prefixes);
  struct attr *attr2;
  attr2  = get_attr_of_event(&time_stamp_ds_head,event_id);
  // zlog_debug ("****  we got the attr  calling get_attr_of_event for RCE_ID: %s",event_id);

  if(attr2==NULL)
    zlog_debug ("****  The attr value for RCE_ID: %s is null!!!!\n",event_id);
  else
  {
    zlog_debug ("****  The attr value for RCE_ID: %s is not null!!!!\n",event_id);
    //zlog_debug("*********** going to add %s as aspathvalue   ********** ",attr2->aspath->str);
  }

  if (list_of_all_prefixes!= NULL)
  {
    if (AS_number_for_next_hop ==10)
      AS_number_for_next_hop = 2;
    if (AS_number_for_next_hop ==20)
      AS_number_for_next_hop = 1;  
    if (AS_number_for_next_hop ==30)
      AS_number_for_next_hop = 3;  

    zlog_debug ("We are sending %d as next AS number in circa_msg_fib_entry_send function to be sent ",AS_number_for_next_hop);
    circa_msg_fib_entry_send (avatar,event_id,list_of_affected_prefixes_str_version,list_of_all_prefixes,&attr2,AS_number_for_next_hop);
  }

    //circa_fib_entry_packet(avatar,event_id,list_of_all_prefixes,attr2);
    
   // circa_msg_fib_entry_send_simple(avatar,event_id);
  }
  // if (avatar)
  // {
  //   zlog_debug ("Sending FIB entries for RCE_ID: %s for %ld affected prefixes from:%ld to:%ld",event_id,number_of_affected_prefixes,avatar->local_as,avatar->as);
  //   bool keep_sending_fib_for_prefixes = true; 
  //   while(keep_sending_fib_for_prefixes && list_of_all_prefixes!=NULL)
  //   {
  //     int a_list_of_prefixes_counter = 0;
  //     struct update_prefix_list * my_sending_prefix_list ;
  //     while(a_list_of_prefixes_counter < 700 && list_of_all_prefixes!=NULL)
  //     {
  //       my_sending_prefix_list ->next= list_of_all_prefixes->next;
  //       a_list_of_prefixes_counter = a_list_of_prefixes_counter +1;
  //     }

  //     if (my_sending_prefix_list !=NULL)
  //     circa_msg_fib_entry_send (avatar,event_id,my_sending_prefix_list);

  //     if (list_of_all_prefixes==NULL)
  //     {
  //       keep_sending_fib_for_prefixes = false;
  //     }
  //   }
  // }
  // zlog_debug ("4 Sending FIB entries for RCE_ID: %s ",event_id);
}


//shahrooz2
/* Make a CIRCA_MSG_FIB_ENTRY packet which include event id, next hop, ASPATH and a list of prefixes */
void
circa_msg_fib_entry_send (struct peer *peer,char * event_id,struct update_prefix_list * update_prefix_list_str_values,struct event_affected_prefix_list * my_sending_prefix_list, struct attr * attr,int next_hop_AS_number)
{
  //zlog_debug ("outgoing CIRCA MSG FIB ENTRY to ground message as next hop as %d",next_hop_AS_number);
  //zlog_debug ("outgoing CIRCA MSG FIB ENTRY to ground message to %s ",peer->host);
  if (avatar)
  {
  // zlog_debug ("2 outgoing CIRCA MSG FIB ENTRY to ground message to %s ",peer->host);
  // }


  //zlog_debug ("***************0*********\n");
  //zlog_debug ("***********the ASPATH is %s *************\n",attr->aspath->str);
  //zlog_debug ("************************\n");

  afi_t afi= AFI_IP;
  safi_t safi = SAFI_UNICAST;

  struct stream *s;
  struct stream *snlri;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct stream *packet;
  struct bgp_node *rn = NULL;
  struct bgp_info *binfo = NULL;
  bgp_size_t total_attr_len = 0;
  unsigned long attrlen_pos = 0;
  int space_remaining = 0;
  int space_needed = 0;
  size_t mpattrlen_pos = 0;
  size_t mpattr_pos = 0;
  size_t mpattr_pos2 = 0;

  s = peer->work;
  stream_reset (s);
  snlri = peer->scratch;
  stream_reset (snlri);
  struct prefix next_prefix;
  struct bgp *bgp;
    struct prefix_rd *prd = NULL;
    u_char *tag = NULL;
    struct peer *from = NULL;
    bgp = peer->bgp;
    from = bgp->peer_self;

    struct attr self_attr;
    struct aspath *self_aspath;

    struct prefix p;
    char buf[SU_ADDRSTRLEN];
    zlog_debug (" lets generate affected prefix!");
  if (afi == AFI_IP)
    str2prefix ("100.100.0.0/0", &p);
  else 
    str2prefix ("100.100.0.0/0", &p);


  struct prefix affected_prefix;

  str2prefix ("100.100.0.0/24", &affected_prefix);
  // zlog_debug (" we generated affected prefix!!!!!!!!!  %s  \n",inet_ntop(affected_prefix.family, &(affected_prefix.u.prefix), buf, INET6_BUFSIZ));

  // zlog_debug (" we generated affected prefix!!!!!!!!!  %s  \n",inet_ntop(affected_prefix.family, &(affected_prefix.u.prefix), buf, INET6_BUFSIZ));

  // struct bgp_info *new;
  // struct bgp_info info;
  struct attr *attr_simple;
  struct attr *attr_new;
  int ret;

  // assert (bgp_static);
  // if (!bgp_static)
  //   return;

  // zlog_debug ("***********we are going to set attr*************\n");

  //bgp_attr_default_set (&attr_simple, BGP_ORIGIN_IGP);
  bgp_attr_default_set (&attr_simple, BGP_ORIGIN_IGP);

  //attr_simple->origin = BGP_ORIGIN_EGP;
  // attr_simple->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);

  // self_aspath =  aspath_str2aspath("3 1");
  // attr_simple->aspath = self_aspath;
  // attr_simple->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);

  // attr_simple->med = 30;
  // attr_simple->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
  // // attr_simple->nexthop = peer->nexthop.v4;
  // // attr_simple->flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);

  // in_addr_t nexthop_h, nexthop_n;
  // nexthop_n = peer->nexthop.v4.s_addr;
  // nexthop_h = ntohl (nexthop_n);
  // attr_simple->nexthop.s_addr = nexthop_n;
  // attr_simple->flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);



  //attr_new = bgp_attr_intern (&attr);



  // zlog_debug (" we set all attributes of attr line 710  \n");
    
  /* create and fill attr data structure */
  //bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
  // aspath = attr.aspath;
  // attr.local_pref = bgp->default_local_pref;
  // memcpy (&attr.nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);


  //bgp_attr_default_set (&self_attr, BGP_ORIGIN_IGP);
  //self_aspath = self_attr.aspath;
  //self_attr.local_pref = bgp->default_local_pref;
  //memcpy (&self_attr.nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);


  // memset (&self_attr, 0, sizeof (struct attr));
  // self_attr.extra = &self_attr;

  // /* Origin attribute. */
  //memcpy (&self_attr.nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);
  //in_addr_t nexthop_h, nexthop_n;
  //nexthop_n = stream_get_ipv4 (peer->ibuf);
  //&self_attr.nexthop.s_addr = peer->nexthop.v4.s_addr;
  //bgp_attr_default_set (&self_attr, BGP_ORIGIN_IGP);

  //attr.origin = origin;
  //self_attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);
  /* AS path attribute. */
  //self_aspath =  aspath_str2aspath("3 1");
  //self_aspath = aspath_add_seq_n (self_aspath, 3, 1);
  //self_attr.aspath = self_aspath;
  // self_attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);
  /* Next hop attribute.  */
  //self_attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);
  //self_attr.weight = BGP_ATTR_DEFAULT_WEIGHT;

  //     char attrstr[BUFSIZ];
  //     attrstr[0] = '\0';
  //     int ret= bgp_dump_attr (peer, &attr, attrstr, BUFSIZ);
  //     if (ret)
  //     {
  // zlog_debug ( "%s we have attr as: rcvd UPDATE w/ attr: %s from %ld",
  //       peer->host, attrstr,peer->as);
  //     }



    // bgp_attr_default_set (&self_attr, BGP_ORIGIN_IGP);
    // self_aspath = self_attr.aspath;
    // self_attr.local_pref = bgp->default_local_pref;
    //memcpy (&self_attr.nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);
    // self_attr.med = 30;
    // //self_attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
    // self_attr.extra->tag = NULL;
    int prefix_counter = 0;
   // zlog_debug ("we created the next hop of created attr variable \n");
    // while (update_prefix_list_str_values!=NULL)
    // {   
      // zlog_debug ("***beginning of the loop");
      //next_prefix = update_prefix_list_str_values ->next;
      //str2prefix ("100.1.1.0/24", &affected_prefix);
  // zlog_debug (" Generated affected prefix in the loop!!!!!!!!!  %s  \n",inet_ntop(affected_prefix.family, &(affected_prefix.u.prefix), buf, INET6_BUFSIZ));

      //update_prefix_list_str_values = update_prefix_list_str_values ->next;
  // zlog_debug (" Generated affected prefix in the loop!!!!!!!!!  %s  \n",inet_ntop(affected_prefix.family, &(affected_prefix.u.prefix), buf, INET6_BUFSIZ));

      /* If packet is empty, set attribute. */
      if (stream_empty (s))
  {
    /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
     * one byte message type.
     */
    s = stream_new (BGP_MAX_PACKET_SIZE);
    bgp_packet_set_marker (s, CIRCA_MSG_FIB_ENTRY);
    // zlog_debug (" we set bgp_packet_set_marker line 648 \n");

      /* 2: Write GRC subcode 2 for GRC message*/
     stream_putl (s, CIRCA_MSG_FIB_ENTRY);
  // zlog_debug ("We wrote CIRCA_MSG_FIB_ENTRY sub code to the streem");
      /* 2: Write seq  number of event id  */
      char * backup_event_id[EVENT_ID_LENGTH];
      strncpy(backup_event_id,event_id,EVENT_ID_LENGTH);
      long router_id_value = str_split(backup_event_id, ',',1);
      long seq_number_sec = str_split(backup_event_id, ',',0);
      /* 2: Write seq  number */
     stream_putl (s, seq_number_sec);
      /* 2: Write seq  number2 as timestamp */
     stream_putl (s, router_id_value);
     if (peer->as ==3)
      stream_putl (s, 2);
    if (peer->as ==2)
      stream_putl (s, 1);
    if (peer->as ==4)
      stream_putl (s, 3);
    if (peer->as ==1)
      stream_putl (s, 1);

    stream_putl (s, 1);
    // zlog_debug (" we set all event id line 663 \n");



    /* 2: withdrawn routes length */
    stream_putw (s, 0);

    /* 3: total attributes length - attrlen_pos stores the position */
    attrlen_pos = stream_get_endp (s);
    stream_putw (s, 0);

    /* 4: if there is MP_REACH_NLRI attribute, that should be the first
     * attribute, according to draft-ietf-idr-error-handling. Save the
     * position.
     */
    mpattr_pos = stream_get_endp(s);

  
    // zlog_debug (" before adding attr the mpattr_pos is %d and total_attr_len is %d \n",mpattr_pos,total_attr_len);
    /* 5: Encode all the attributes, except MP_REACH_NLRI attr. */
    //total_attr_len = bgp_packet_attribute (NULL, peer, s, attr, &p, afi, safi, from, NULL, NULL);
    str2prefix ("100.100.0.0/24", &affected_prefix);
    //total_attr_len = circa_packet_attribute (NULL, peer, s, &attr_simple, affected_prefix, AFI_IP, SAFI_UNICAST, from, NULL, NULL);// working
   // total_attr_len = bgp_packet_attribute (NULL, peer, s, &self_attr, &p, afi, safi, from, NULL, NULL);// last used and 
        /* 5: Encode all the attributes, except MP_REACH_NLRI attr. */
    // if (afi == AFI_IP && safi == SAFI_UNICAST)
    //   zlog_debug ("we will add prefix because  afi == AFI_IP && safi == SAFI_UNICAST");
    // zlog_debug ("we checked if we will add prefix because  afi == AFI_IP && safi == SAFI_UNICAST");
    //total_attr_len = bgp_packet_attribute (NULL, peer, s,&attr_simple,((afi == AFI_IP && safi == SAFI_UNICAST) ? &p : NULL),afi, safi,from, prd, tag);
  //zlog_debug (" Used affected prefix in the loop!!!!!!!!! with p is  %s  \n",inet_ntop(p.family, &(p.u.prefix), buf, INET6_BUFSIZ));
    str2prefix ("100.100.0.0/24", &affected_prefix);

    total_attr_len = circa_packet_attribute (NULL, peer, s, &attr_simple, &next_prefix, afi, safi, from, NULL, NULL,next_hop_AS_number);// not working
     mpattr_pos2 = stream_get_endp(s);
     // zlog_debug ("we added attr and the mpattr_pos2 now is  %d and total_attr_len is %d \n",mpattr_pos2,total_attr_len);

    }
      if (1==1)
  //stream_put_prefix (s, &rn->p);
  {
    str2prefix ("100.100.0.0/24", &affected_prefix);
    stream_put_prefix (s, &affected_prefix);
    zlog_debug ("************ we added our first prefix to the stream  ************");
  }
  //     else
  // {
  //   /* Encode the prefix in MP_REACH_NLRI attribute */
  //   zlog_debug (" Encode the prefix in MP_REACH_NLRI line 713 \n");
  //   struct prefix_rd *prd = NULL;
  //   u_char *tag = NULL;
  //   if (stream_empty(snlri))
  //     mpattrlen_pos = bgp_packet_mpattr_start(snlri, afi, safi,
  //               &self_attr);
  //   zlog_debug (" Encode the prefix in MP_REACH_NLRI line 719 \n");
  //   bgp_packet_mpattr_prefix(snlri, afi, safi, &p, prd, tag);
  //   zlog_debug (" bgp_packet_mpattr_prefix line 706 \n");

  // }

  // zlog_debug (" used affected prefix in loop was   %s  \n",inet_ntop(affected_prefix.family, &(affected_prefix.u.prefix), buf, INET6_BUFSIZ));
  //str2prefix ("100.1.1.0/24", &affected_prefix);
  // zlog_debug (" used affected prefix in loop was   %s  \n",inet_ntop(affected_prefix.family, &(affected_prefix.u.prefix), buf, INET6_BUFSIZ));

     //}
// zlog_debug (" ******** We are out of while loop ********* \n");
  if (! stream_empty (s))
    {
      if (!stream_empty(snlri))
  {
    //bgp_packet_mpattr_end(snlri, mpattrlen_pos);
    total_attr_len += stream_get_endp(snlri);
    // zlog_debug (" ******** now after bgp_packet_mpattr_end the total_attr_len is %d ********* \n",total_attr_len);
  }
      /* set the total attribute length correctly */
  // zlog_debug (" ******** set the total attribute length correctly attrlen_pos is %d , total_attr_len is %d ********* \n",attrlen_pos,total_attr_len);
      stream_putw_at (s, attrlen_pos, total_attr_len);
      if (!stream_empty(snlri))
      {
      // zlog_debug (" ******** we added packet = stream_dupcat(s, snlri, mpattr_pos); ********* \n");
      packet = stream_dupcat(s, snlri, mpattr_pos);
      }
      else
      {
      // zlog_debug (" ******** we added packet = stream_dup (s);; ********* \n");
      packet = stream_dup (s);
    }
      bgp_packet_set_size (packet);
      bgp_packet_add (peer, packet);
      BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
      stream_reset (s);
      stream_reset (snlri);
      zlog_debug ("we are at the point of returning packet to be sent down to %s \n",peer->host);
      return packet;
    }
  zlog_debug ("we are at the point of returning NULL packet to be sent down to %s \n",peer->host);
  return NULL;
}
  }

  //     if (afi == AFI_IP && safi == SAFI_UNICAST)
  // //stream_put_prefix (s, &rn->p);
  // stream_put_prefix (s, next_prefix);
  //     else
  // {
  //   /* Encode the prefix in MP_REACH_NLRI attribute */
  //   zlog_debug (" Encode the prefix in MP_REACH_NLRI line 692 \n");
  //   struct prefix_rd *prd = NULL;
  //   u_char *tag = NULL;
  //   if (stream_empty(snlri))
  //     mpattrlen_pos = bgp_packet_mpattr_start(snlri, afi, safi,
  //               attr);
  //   bgp_packet_mpattr_prefix(snlri, afi, safi, next_prefix, prd, tag);
  //   zlog_debug (" bgp_packet_mpattr_prefix line 706 \n");

  // }
  //     zlog_debug ("We added prefix  %s to the fib packet\n",next_prefix);

  //   }

  // if (! stream_empty (s))
  //   {
  //     if (!stream_empty(snlri))
  // {
  //   bgp_packet_mpattr_end(snlri, mpattrlen_pos);
  //   total_attr_len += stream_get_endp(snlri);
  // }
  //     /* set the total attribute length correctly */
  //     stream_putw_at (s, attrlen_pos, total_attr_len);
  //     if (!stream_empty(snlri))
  // packet = stream_dupcat(s, snlri, mpattr_pos);
  //     else
  // packet = stream_dup (s);
  //     bgp_packet_set_size (packet);
  //     bgp_packet_add (peer, packet);
  //     BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
  //     stream_reset (s);
  //     stream_reset (snlri);
  //     return packet;
  //   }
  // return NULL;
//   while (my_sending_prefix_list!=NULL)
//     {
//       next_prefix = my_sending_prefix_list ->next;
//       //struct prefix next_prefix;
//       zlog_debug (" 613 we got next prefix %s \n",next_prefix);
//       my_sending_prefix_list = my_sending_prefix_list ->next;
//       zlog_debug (" 615 we got next prefix and updated the list \n");

//   //     assert (adv->rn);
//   //     rn = adv->rn;
//   //     adj = adv->adj;
//   //     if (adv->binfo)
//   //       binfo = adv->binfo;

//   //     space_remaining = STREAM_CONCAT_REMAIN (s, snlri, STREAM_SIZE(s)) -
//   //                       BGP_MAX_PACKET_SIZE_OVERFLOW;
//   //     space_needed = BGP_NLRI_LENGTH + bgp_packet_mpattr_prefix_size (afi, safi, &rn->p);

//   //     /* When remaining space can't include NLRI and it's length.  */
//   //     if (space_remaining < space_needed)
//   // break;

//       /* If packet is empty, set attribute. */
//       if (stream_empty (s))
//   {
//     // struct prefix_rd *prd = NULL;
//     // u_char *tag = NULL;
//     // struct peer *from = NULL;

//     // if (rn->prn)
//     //   prd = (struct prefix_rd *) &rn->prn->p;
//     //       if (binfo)
//     //         {
//     //           from = binfo->peer;
//     //           if (binfo->extra)
//     //             tag = binfo->extra->tag;
//     //         }

//     /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
//      * one byte message type.
//      */
//   s = stream_new (BGP_MAX_PACKET_SIZE);
//   bgp_packet_set_marker (s, CIRCA_MSG_FIB_ENTRY);
//   zlog_debug (" we got bgp_packet_set_marker line 648 \n");

//     /* 2: Write GRC subcode 2 for GRC message*/
//    stream_putl (s, CIRCA_MSG_FIB_ENTRY);
// //zlog_debug ("We wrote CIRCA_MSG_FIB_ENTRY sub code to the streem");
//     /* 2: Write seq  number of event id  */
//     char * backup_event_id[EVENT_ID_LENGTH];
//     strncpy(backup_event_id,event_id,EVENT_ID_LENGTH);
//     long router_id_value = str_split(backup_event_id, ',',1);
//     long seq_number_sec = str_split(backup_event_id, ',',0);
//     /* 2: Write seq  number */
//    stream_putl (s, seq_number_sec);
//     /* 2: Write seq  number2 as timestamp */
//    stream_putl (s, router_id_value);

//   zlog_debug (" we set all event id line 663 \n");

//     /* 4: if there is MP_REACH_NLRI attribute, that should be the first
//      * attribute, according to draft-ietf-idr-error-handling. Save the
//      * position.
//      */
//     mpattr_pos = stream_get_endp(s);
//     struct prefix_rd *prd = NULL;
//     u_char *tag = NULL;
//     struct peer *from = NULL;
//     zlog_debug (" we stream_get_endp line 673 \n");
//     struct attr *attr2;
//     /* 5: Encode all the attributes, except MP_REACH_NLRI attr. */
//     total_attr_len = bgp_packet_attribute (NULL, peer, s, attr, next_prefix, afi, safi, from, NULL, NULL);

//      zlog_debug (" we did set attr line 683 \n");

//   }
//       if (afi == AFI_IP && safi == SAFI_UNICAST)
//   //stream_put_prefix (s, &rn->p);
//   stream_put_prefix (s, next_prefix);
//       else
//   {
//     /* Encode the prefix in MP_REACH_NLRI attribute */
//     zlog_debug (" Encode the prefix in MP_REACH_NLRI line 692 \n");
//     struct prefix_rd *prd = NULL;
//     u_char *tag = NULL;
//     if (stream_empty(snlri))
//       mpattrlen_pos = bgp_packet_mpattr_start(snlri, afi, safi,
//                 attr);
//     bgp_packet_mpattr_prefix(snlri, afi, safi, next_prefix, prd, tag);
//     zlog_debug (" bgp_packet_mpattr_prefix line 706 \n");

//   }
//       zlog_debug ("We added prefix  %s to the fib packet\n",next_prefix);

//     }

//   if (! stream_empty (s))
//     {
//       if (!stream_empty(snlri))
//   {
//     bgp_packet_mpattr_end(snlri, mpattrlen_pos);
//     total_attr_len += stream_get_endp(snlri);
//   }
//       /* set the total attribute length correctly */
//       stream_putw_at (s, attrlen_pos, total_attr_len);
//       if (!stream_empty(snlri))
//   packet = stream_dupcat(s, snlri, mpattr_pos);
//       else
//   packet = stream_dup (s);
//       bgp_packet_set_size (packet);
//       bgp_packet_add (peer, packet);
//       BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
//       stream_reset (s);
//       stream_reset (snlri);
//       return packet;
//     }
//   return NULL;


void
circa_msg_fib_entry_send_simple (struct peer *peer,char * event_id)
{

  if (peer->status == Established){
  zlog_debug ("outgoing CIRCA MSG FIB ENTRY to ground message to %s ",peer->host);
  afi_t afi;
  safi_t safi;
  struct stream *s;
  struct stream *snlri;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct stream *packet;
  struct bgp_node *rn = NULL;
  struct bgp_info *binfo = NULL;
  bgp_size_t total_attr_len = 0;
  unsigned long attrlen_pos = 0;
  int space_remaining = 0;
  int space_needed = 0;
  size_t mpattrlen_pos = 0;
  size_t mpattr_pos = 0;


  s = peer->work;
  stream_reset (s);
  snlri = peer->scratch;
  stream_reset (snlri);

      /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
     * one byte message type.
     */
  s = stream_new (BGP_MAX_PACKET_SIZE);
  bgp_packet_set_marker (s, CIRCA_MSG_FIB_ENTRY);

    /* 2: Write GRC subcode 2 for GRC message*/
   stream_putl (s, CIRCA_MSG_FIB_ENTRY);
//zlog_debug ("We wrote CIRCA_MSG_FIB_ENTRY sub code to the streem");
    /* 2: Write seq  number of event id  */

    char * backup_event_id[EVENT_ID_LENGTH];
    strncpy(backup_event_id,event_id,EVENT_ID_LENGTH);

    long router_id_value = str_split(backup_event_id, ',',1);

    long seq_number_sec = str_split(backup_event_id, ',',0);
    /* 2: Write seq  number */
   stream_putl (s, seq_number_sec);

    /* 2: Write seq  number2 as timestamp */

   stream_putl (s, router_id_value);

   // zlog_debug ("We wrote local_as  to the streem");

   //struct prefix* p;
   // zlog_debug ("We defined prefix");
   // strncpy(&p.u.prefix,"88.88.0.0/24",10);

    /* adding next hop */
   // if (attr->nexthop.s_addr == 0)
   //    stream_put_ipv4 (s, peer->nexthop.v4.s_addr);
    // else
    //   stream_put_ipv4 (s, attr->nexthop.s_addr);
   //  /* adding aspath */
   //  size_t aspath_sizep;
   //  struct aspath *aspath;
   //  int use32bit = 1;

   //  aspath = aspath_dup (attr->aspath);
   //  stream_putc (s, BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
   //  stream_putc (s, BGP_ATTR_AS_PATH);
   //  aspath_sizep = stream_get_endp (s);
   //  stream_putw (s, 0);
   //  stream_putw_at (s, aspath_sizep, aspath_put (s, aspath, use32bit));

    /* adding prefix */
   //stream_put_prefix (s, p);
// zlog_debug ("We copied value to stream");
    /* 2: Write next hop */

    /* 2: write aspath */
  // int use32bit = (CHECK_FLAG (peer->cap, PEER_CAP_AS4_RCV)) ? 1 : 0;
  // struct aspath* aspath;
  // zlog_debug ("We defined aspath  to the streem");
  // strncpy(&aspath.str,"30 20 10",10);
  // zlog_debug ("We wrote aspath to aspath");
  // int aspath_sizep = stream_get_endp (s);
  // zlog_debug ("We got endp of the streem");
  // stream_putw (s, 0);
  // stream_putw_at (s, aspath_sizep, aspath_put (s, aspath, use32bit));
  // zlog_debug ("We wrote aspath  to the streem");

    stream_putw (s, 0);
// zlog_debug ("We wrote 0  to the streem");

    /* 3: total attributes length - attrlen_pos stores the position */
    attrlen_pos = stream_get_endp (s);

    stream_putw (s, 0);
// zlog_debug ("We wrote 0  to the streem");


    /* 4: if there is MP_REACH_NLRI attribute, that should be the first
     * attribute, according to draft-ietf-idr-error-handling. Save the
     * position.
     */
    mpattr_pos = stream_get_endp(s);
    packet = stream_dup (s);
    bgp_packet_set_size (packet);
    bgp_packet_add (peer, packet);
    BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
    stream_reset (s);
    stream_reset (snlri);
    zlog_debug ("We are at the returning packet point for sending CIRCA FIB ENTRY MSG for root cause event %s  to %s",event_id, peer->host);    
    return packet;
  }
}

/* Make CIRCA_GRC_MSG packet and send it to the peer. */
void
circa_grc_msg_send (struct peer *peer,uint32_t grc_sub_code,uint32_t *target_router_id)
{

  if (peer->status == Established){
  zlog_debug ("outgoing CIRCA MSG message to %s ",peer->host);
  afi_t afi;
  safi_t safi;
  struct stream *s;
  struct stream *snlri;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct stream *packet;
  struct bgp_node *rn = NULL;
  struct bgp_info *binfo = NULL;
  bgp_size_t total_attr_len = 0;
  unsigned long attrlen_pos = 0;
  int space_remaining = 0;
  int space_needed = 0;
  size_t mpattrlen_pos = 0;
  size_t mpattr_pos = 0;

  /* define a new unique root cause event id */
  sequence_number_for_event_ids = sequence_number_for_event_ids +1;

  long seq_number_sec = sequence_number_for_event_ids;
  s = peer->work;
  stream_reset (s);
  snlri = peer->scratch;
  stream_reset (snlri);

      /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
     * one byte message type.
     */
  s = stream_new (BGP_MAX_PACKET_SIZE);
  bgp_packet_set_marker (s, CIRCA_MSG_GRC);

    /* 2: Write GRC subcode 2 for GRC message*/
   stream_putl (s, grc_sub_code);


    /* 2: Write seq  number */
   stream_putl (s, seq_number_sec);

    /* 2: Write seq  number2 as timestamp */

   stream_putl (s, seq_number_sec);

    /* 2: Write root cause event ID */
   stream_putl (s, target_router_id);
   stream_putl (s, target_router_id);
   stream_putl (s, target_router_id);
   stream_putl (s, target_router_id);

    /* 2: withdrawn routes length */
    stream_putw (s, 0);

    /* 3: total attributes length - attrlen_pos stores the position */
    attrlen_pos = stream_get_endp (s);

    stream_putw (s, 0);
    /* 4: if there is MP_REACH_NLRI attribute, that should be the first
     * attribute, according to draft-ietf-idr-error-handling. Save the
     * position.
     */
    mpattr_pos = stream_get_endp(s);
    packet = stream_dup (s);
    bgp_packet_set_size (packet);
    bgp_packet_add (peer, packet);
    BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
    stream_reset (s);
    stream_reset (snlri);
    zlog_debug ("We are at the returning packet point for sending CIRCA GRC MSG with event id %s to %s",global_event_id, peer->host);    
    return packet;
  }
}


/* Make CIRCA FIB packet for sending down next hop for a list of prefixes */
//shahrooz
void
circa_fib_entry_packet (struct peer * peer,char * event_id,struct event_affected_prefix_list * my_sending_prefix_list, struct attr * attr)
{
  zlog_debug ("we are sending down the fib entry for a list of prefixes to %ld" ,peer->as);

  if(avatar)
  {
  // zlog_debug ("!!!!!!!!!!!!!!!!!!!!!!!!!!! We are at the bgp_update_packet to send an update to %s", peer->host);    
  afi_t afi;
  safi_t safi;
  struct stream *s;
  struct stream *snlri;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct stream *packet;
  struct bgp_node *rn = NULL;
  struct bgp_info *binfo = NULL;
  bgp_size_t total_attr_len = 0;
  unsigned long attrlen_pos = 0;
  int space_remaining = 0;
  int space_needed = 0;
  size_t mpattrlen_pos = 0;
  size_t mpattr_pos = 0;
  char buf[SU_ADDRSTRLEN];
  s = peer->work;
  stream_reset (s);
  snlri = peer->scratch;
  stream_reset (snlri);
  long next_hop_AS_number;
  struct prefix *next_prefix;
  struct bgp *bgp;
  struct attr self_attr;
  struct aspath *self_aspath;
  bgp_attr_default_set (&self_attr, BGP_ORIGIN_IGP);
  self_aspath = self_attr.aspath;
  self_attr.local_pref = bgp->default_local_pref;
  memcpy (&self_attr.nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);
  self_attr.med = 30;
  self_attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
  self_attr.extra->tag = NULL;
  int prefix_counter = 0;
  /* we define a peer as the sender of the update message we are sending. 
  If we are the owner of the prefix or we have not received the prefix durin this root cause event,
   we will set the sender to NULL */
  if(peer->as == 4)
    next_hop_AS_number = 3;
  if(peer->as == 3)
    next_hop_AS_number = 2;
  if(peer->as == 2)
    next_hop_AS_number = 1;
  if(peer->as == 1)
    next_hop_AS_number = 1;


  while (my_sending_prefix_list !=NULL)
    {
      prefix_counter = prefix_counter+1;
      next_prefix = my_sending_prefix_list->next;
      my_sending_prefix_list = my_sending_prefix_list ->next;
      /* If packet is empty, set attribute. */
      if (stream_empty (s))
  {
    struct prefix_rd *prd = NULL;
    u_char *tag = NULL;
    struct peer *from = NULL;

    
    /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
     * one byte message type.
     */
    bgp_packet_set_marker (s, CIRCA_MSG_FIB_ENTRY);
    zlog_debug (" we got bgp_packet_set_marker line 648 \n");
    /* 2: Write GRC subcode 2 for GRC message*/
    stream_putl (s, CIRCA_MSG_FIB_ENTRY);
    zlog_debug ("We wrote CIRCA_MSG_FIB_ENTRY sub code to the streem");
    /* 2: Write seq  number of event id  */
    char * backup_event_id[EVENT_ID_LENGTH];
    strncpy(backup_event_id,event_id,EVENT_ID_LENGTH);
    long router_id_value = str_split(backup_event_id, ',',1);
    long seq_number_sec = str_split(backup_event_id, ',',0);
    /* 2: Write seq  number */
    stream_putl (s, seq_number_sec);
    /* 2: Write seq  number2 as timestamp */
    stream_putl (s, router_id_value);
    stream_putl (s, next_hop_AS_number);
    stream_putl (s, next_hop_AS_number);

    /* 2: withdrawn routes length */
    stream_putw (s, 0);

    /* 3: total attributes length - attrlen_pos stores the position */
    attrlen_pos = stream_get_endp (s);
    stream_putw (s, 0);

    /* 4: if there is MP_REACH_NLRI attribute, that should be the first
     * attribute, according to draft-ietf-idr-error-handling. Save the
     * position.
     */
    mpattr_pos = stream_get_endp(s);

    /* 5: Encode all the attributes, except MP_REACH_NLRI attr. */
    total_attr_len = bgp_packet_attribute (NULL, peer, s, &self_attr, &next_prefix, afi, safi, from, NULL, NULL);// working 

  }

      if (afi == AFI_IP && safi == SAFI_UNICAST)
  stream_put_prefix (s, &next_prefix);
      else
  {
    /* Encode the prefix in MP_REACH_NLRI attribute */
    struct prefix_rd *prd = NULL;
    u_char *tag = NULL;



    if (stream_empty(snlri))
      mpattrlen_pos = bgp_packet_mpattr_start(snlri, afi, safi,
                &self_attr);
    bgp_packet_mpattr_prefix(snlri, afi, safi, &next_prefix, prd, tag);
  }

    if (BGP_DEBUG (update, UPDATE_OUT))
      {
        char buf[INET6_BUFSIZ];
        zlog_debug ("************************* we added prefix  in fib entry %s/%d ",inet_ntop (next_prefix->family, &(next_prefix->u.prefix), buf, INET6_BUFSIZ),next_prefix->prefixlen);
        // zlog (peer->log, LOG_DEBUG, "%s added prefix %s/%d",
        //       peer->host,
        //       inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ),
        //       rn->p.prefixlen);
      }

      /* Synchnorize attribute.  */
  //     if (adj->attr)
  // bgp_attr_unintern (&adj->attr);
  //     else
  // peer->scount[afi][safi]++;

  //     adj->attr = bgp_attr_intern (adv->baa->attr);

  //     adv = bgp_advertise_clean (peer, adj, afi, safi);
    }

  if (! stream_empty (s))
    {
      if (!stream_empty(snlri))
  {
    bgp_packet_mpattr_end(snlri, mpattrlen_pos);
    total_attr_len += stream_get_endp(snlri);
  }

      /* set the total attribute length correctly */
      stream_putw_at (s, attrlen_pos, total_attr_len);

      if (!stream_empty(snlri))
  packet = stream_dupcat(s, snlri, mpattr_pos);
      else
  packet = stream_dup (s);
      bgp_packet_set_size (packet);
      bgp_packet_add (peer, packet);
      BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
      stream_reset (s);
      stream_reset (snlri);
      zlog_debug ("we finished building the fib entry message including %ld prefixes to %ld" ,prefix_counter,peer->as);
      return packet;
    }
  }
  return NULL;
}


/* Make BGP update packet using CIRCA compatible function.  */
static struct stream *
circa_update_packet (struct peer *peer, afi_t afi, safi_t safi)
{
  zlog_debug ("we are sending message to %ld" ,peer->as);
  int snumber_of_sent_prefix_counter = 0;
  // zlog_debug ("!!!!!!!!!!!!!!!!!!!!!!!!!!! We are at the bgp_update_packet to send an update to %s", peer->host);    
  /* lets set the peer_list_for_sending_head value to NULL as we got a new packet */
  peer_list_for_sending_head = NULL;
  if(avatar)
  {
    if (strcmp(peer->host,avatar->host)==0)
      return NULL;
  }
  // zlog_debug ("!!!!!!!!!!!!!!!!!!!!!!!!!!! We are at the bgp_update_packet to send an update to %s", peer->host);    

  struct stream *s;
  struct stream *snlri;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct stream *packet;
  struct bgp_node *rn = NULL;
  struct bgp_info *binfo = NULL;
  bgp_size_t total_attr_len = 0;
  unsigned long attrlen_pos = 0;
  int space_remaining = 0;
  int space_needed = 0;
  size_t mpattrlen_pos = 0;
  size_t mpattr_pos = 0;
  char buf[SU_ADDRSTRLEN];
  s = peer->work;
  stream_reset (s);
  snlri = peer->scratch;
  stream_reset (snlri);

  /* we define a peer as the sender of the update message we are sending. 
  If we are the owner of the prefix or we have not received the prefix durin this root cause event,
   we will set the sender to NULL */
  struct peer * sender_peer;
  adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->update);
  bool we_are_owner = false;
  if(strcmp("Static announcement",adv->binfo->peer->host)==0)
  {
    // zlog_debug ("************************\n");
    // zlog_debug ("************************\n");
    // zlog_debug ("************we are the owner of these prefixes************\n");
    // zlog_debug ("************************\n");
    // zlog_debug ("************************\n");
    we_are_owner = true;
  }
  if(strcmp("Static announcement",adv->binfo->peer->host)!=0){
    // zlog_debug ("************************\n");
    // //zlog_debug ("***********the ASPATH is %s %s*************\n",adv->baa->attr->aspath->str,adv->baa->attr->nexthop.s_addr);
    // zlog_debug ("************************\n");
    we_are_owner = false;
  }

  

  int first_prefix_in_list = 1;
  bool first_prefix_on_origin_list = true;

  while (adv)
    {
      assert (adv->rn);
      rn = adv->rn;
      adj = adv->adj;
      if (adv->binfo)
        binfo = adv->binfo;

      space_remaining = STREAM_CONCAT_REMAIN (s, snlri, STREAM_SIZE(s)) -
                        BGP_MAX_PACKET_SIZE_OVERFLOW;
      space_needed = BGP_NLRI_LENGTH + bgp_packet_mpattr_prefix_size (afi, safi, &rn->p);

      /* When remaining space can't include NLRI and it's length.  */
      if (space_remaining < space_needed)
  break;

      /* If packet is empty, set attribute. */
      if (stream_empty (s))
  {
    struct prefix_rd *prd = NULL;
    u_char *tag = NULL;
    struct peer *from = NULL;

    if (rn->prn)
      prd = (struct prefix_rd *) &rn->prn->p;
          if (binfo)
            {
              from = binfo->peer;
              if (binfo->extra)
                tag = binfo->extra->tag;
            }

    /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
     * one byte message type.
     */
    bgp_packet_set_marker (s, CIRCA_MSG_UPDATE);
    /* here we will generate a new unique time stamp for our sending packet */
    char * caused_time_stamp[TIME_STAMP_LENGTH];
    char * root_cause_event_id[EVENT_ID_LENGTH];
    char * to_be_sent_time_stamp[TIME_STAMP_LENGTH];
    strncpy(to_be_sent_time_stamp,"unknown",TIME_STAMP_LENGTH);
    char * router_id[20];
    sprintf(router_id, "%u", peer->local_as);
    /* lets generate a new unique time stamp */
    char as_path_str[50];
    strncpy(as_path_str,adv->baa->attr->aspath->str,50);
    struct peer * sender_peer_of_prefix = NULL;
    char * prefix_value[PREFIX_LENGTH];

    concat_prefix_length(inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ),rn->p.prefixlen,prefix_value,PREFIX_LENGTH);

    if (!we_are_owner)
    {
        //zlog_debug("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++This is  ASPATH of this prefix  %s %sdddd ",inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ),adv->baa->attr->aspath->str);
        char my_delim[]= " ";
        char *my_ptr = strtok(as_path_str, my_delim);
        int my_aspath_array[4];
        int i=0;
        while(my_ptr != NULL)
        {
            my_aspath_array[i] =atoi(my_ptr);
            i = i+1;
            my_ptr = strtok(NULL, my_delim);
        }
        // zlog_debug(" +++++++++++++++++++++++++++++++++++++this prefix is not belong to us  a ASPATH %d and prefix %s", my_aspath_array[0],prefix_value);
        // print_time_stamp(&time_stamp_ds_head);
        // zlog_debug(" go to check received prefix event id time stam");

        if(check_if_we_have_received_prefix(&time_stamp_ds_head,prefix_value,my_aspath_array[0],adv->baa->attr->aspath->str))
        {
            int ret;
            // zlog_debug(" go to get event id time stam");
           ret = get_event_id_time_stamp(&time_stamp_ds_head,prefix_value,my_aspath_array[0],&root_cause_event_id,&caused_time_stamp);
          // zlog_debug(" got event id time stam %s %s",root_cause_event_id,caused_time_stamp);
          // zlog_debug(" got event id time stam2 %s %s",root_cause_event_id,caused_time_stamp);
           if (ret >0)
           {
            int ret2;
            ret2 = filling_data_structure_for_un_root_router(&root_cause_event_id,&to_be_sent_time_stamp,caused_time_stamp,prefix_value,peer,first_prefix_in_list);
            first_prefix_in_list = 0;
            if(ret2<0)
            {
              filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_on_origin_list);
              first_prefix_on_origin_list = false;
            }
           }
           else{
              // zlog_debug("+++++++++++++++22++++++++++++++++++++++++We have received this prefix but we did not get any time tamp for it !!! %s",prefix_value);
              filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_on_origin_list);
              first_prefix_on_origin_list = false;
           }
        }

      else
        {
          // zlog_debug("+1+++++++++++++++++++++++++++++++++++++++We have not received this prefix or we have received but in converged events %s",prefix_value);
          // zlog_debug("++++++++++++++++++++++++++++++++++++++++We will get event id from GRC message");
          // zlog_debug("++++++++++++++++++++++++++++++++++++++++This prefix is belong to us  %s %s ",prefix_value,adv->baa->attr->aspath->str);
          // zlog_debug("++++++++++++++++++++++++++++++++++++++++We will get event id from GRC message");
          filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_on_origin_list);
          first_prefix_on_origin_list = false;
          // zlog_debug("+1.1.1.+++++++++++++++++++++++++++++++++++++++ the current event id being used is  %s",root_cause_event_id);
        }
      }
  else
        {
          // zlog_debug("+2+++++++++++++++++++++++++++++++++++++++We have not received this prefix %s",prefix_value);
          // zlog_debug("++++++++++++++++++++++++++++++++++++++++We will get event id from GRC message");
          // zlog_debug("++++++++++++++++++++++++++++++++++++++++This prefix is belong to us  %s %s ",prefix_value,adv->baa->attr->aspath->str);
          // zlog_debug("++++++++++++++++++++++++++++++++++++++++We will get event id from GRC message");
          filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_on_origin_list);
          first_prefix_on_origin_list = false;
          // zlog_debug("+2.2.2+++++++++++++++++++++++++++++++++++++++ the current event id being used is  %s",root_cause_event_id);
          // zlog_debug("********** this is global event id %s **********",root_cause_event_id);
        }

      if (strcmp(to_be_sent_time_stamp,"unknown")==0)
    {
          // zlog_debug("++++++++++++++++++++++++++++++++++++++++in sending  to %s the to_be_sent_time_stamp value is %s",peer->host,to_be_sent_time_stamp);
          filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_on_origin_list);
          first_prefix_on_origin_list = false;
    }

    // zlog_debug("+4+++++++++++++++++++++++++++++++++++++++lets send to  %s and root_cause_event_id is %s",peer->host, root_cause_event_id);

    long router_id_value;
    char * backup_event_id[EVENT_ID_LENGTH];
    strncpy(backup_event_id,root_cause_event_id,EVENT_ID_LENGTH);
    // zlog_debug("+5+++++++++++++++++++++++++++++++++++++++lets send to  %s %s",peer->host,backup_event_id);

    router_id_value = str_split(backup_event_id, ',',1);
    // zlog_debug("+6+++++++++++++++++++++++++++++++++++++++lets send to  %s %s",peer->host,backup_event_id);

    long seq_number_sec = str_split(backup_event_id, ',',0);
    /* add CBGP sybtype */
    // zlog_debug("we are sending %ld as CIRCA_MSG_UPDATE to %s",CIRCA_MSG_UPDATE,peer->host);
    stream_putl (s, CIRCA_MSG_UPDATE);
    /* add root cause event id */
    // zlog_debug("we are sending %s as event id to %s",backup_event_id,peer->host);

    // zlog_debug("we are sending %ld as seq_number_sec_of_event_id to %s %s",seq_number_sec,peer->host,root_cause_event_id);

    stream_putl (s, seq_number_sec);
    // zlog_debug("we are sending %ld as  router_id_value_of_event id to %s %s",router_id_value,peer->host,root_cause_event_id);
    stream_putl (s, router_id_value);
    /* add time stamp */
    long router_value_in_time_stamp;
    char backup_time_stam[TIME_STAMP_LENGTH];

    strncpy(backup_time_stam,to_be_sent_time_stamp,EVENT_ID_LENGTH);

    router_value_in_time_stamp = str_split(backup_time_stam, ',',1);
    // zlog_debug("this is our time stamp after getting router value of it  %s  ",to_be_sent_time_stamp);
    long seq_number_part_of_time_stamp = str_split(backup_time_stam, ',',0);
    // zlog_debug("we are sending %ld as seq_number_part_of_time_stamp  to %s %s",seq_number_part_of_time_stamp,peer->host,to_be_sent_time_stamp);

    stream_putl (s, seq_number_part_of_time_stamp);
    // zlog_debug("we are sending %ld as  router_value_in_time_stamp to %s %s",router_value_in_time_stamp,peer->host,to_be_sent_time_stamp);

    stream_putl (s, router_value_in_time_stamp);


    /* 2: withdrawn routes length */
    stream_putw (s, 0);

    /* 3: total attributes length - attrlen_pos stores the position */
    attrlen_pos = stream_get_endp (s);
    stream_putw (s, 0);

    /* 4: if there is MP_REACH_NLRI attribute, that should be the first
     * attribute, according to draft-ietf-idr-error-handling. Save the
     * position.
     */
    mpattr_pos = stream_get_endp(s);

    /* 5: Encode all the attributes, except MP_REACH_NLRI attr. */
    total_attr_len = bgp_packet_attribute (NULL, peer, s,
                                           adv->baa->attr,
                                                 ((afi == AFI_IP && safi == SAFI_UNICAST) ?
                                                  &rn->p : NULL),
                                                 afi, safi,
                                           from, prd, tag);
          space_remaining = STREAM_CONCAT_REMAIN (s, snlri, STREAM_SIZE(s)) -
                            BGP_MAX_PACKET_SIZE_OVERFLOW;
          space_needed = BGP_NLRI_LENGTH + bgp_packet_mpattr_prefix_size (afi, safi, &rn->p);;

          /* If the attributes alone do not leave any room for NLRI then
           * return */
          if (space_remaining < space_needed)
            {
              zlog_err ("%s cannot send UPDATE, the attributes do not leave "
                        "room for NLRI", peer->host);
              /* Flush the FIFO update queue */
              while (adv)
                adv = bgp_advertise_clean (peer, adv->adj, afi, safi);
              return NULL;
            } 

  }

      if (afi == AFI_IP && safi == SAFI_UNICAST)
      {
        zlog_debug("we are adding the prefix %s  in the afi == AFI_IP && safi == SAFI_UNICAST if condition",inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ));
  stream_put_prefix (s, &rn->p);
}
      else
  {
    zlog_debug("we are in else of  in the afi == AFI_IP && safi == SAFI_UNICAST if condition",inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ));
    /* Encode the prefix in MP_REACH_NLRI attribute */
    struct prefix_rd *prd = NULL;
    u_char *tag = NULL;

    if (rn->prn)
      prd = (struct prefix_rd *) &rn->prn->p;
    if (binfo && binfo->extra)
      tag = binfo->extra->tag;

    if (stream_empty(snlri))
      mpattrlen_pos = bgp_packet_mpattr_start(snlri, afi, safi,
                adv->baa->attr);
    bgp_packet_mpattr_prefix(snlri, afi, safi, &rn->p, prd, tag);
  }
  snumber_of_sent_prefix_counter = snumber_of_sent_prefix_counter +1;

      if (BGP_DEBUG (update, UPDATE_OUT))
        {
          char buf[INET6_BUFSIZ];

          zlog (peer->log, LOG_DEBUG, "%s send UPDATE %s/%d",
                peer->host,
                inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ),
                rn->p.prefixlen);
        }

      /* Synchnorize attribute.  */
      if (adj->attr)
  bgp_attr_unintern (&adj->attr);
      else
  peer->scount[afi][safi]++;

      adj->attr = bgp_attr_intern (adv->baa->attr);

      adv = bgp_advertise_clean (peer, adj, afi, safi);
    }

  if (! stream_empty (s))
    {
      if (!stream_empty(snlri))
  {
    bgp_packet_mpattr_end(snlri, mpattrlen_pos);
    total_attr_len += stream_get_endp(snlri);
    zlog_debug ("**** total_attr_len after bgp_packet_mpattr_end is %d",total_attr_len);
  }
      zlog_debug ("**** set the total attribute length correctly and attrlen_pos is %d and total_attr_len is %d",attrlen_pos,total_attr_len);
      /* set the total attribute length correctly */
      stream_putw_at (s, attrlen_pos, total_attr_len);

      if (!stream_empty(snlri))
      {
      zlog_debug (" ******** we added packet = stream_dupcat(s, snlri, mpattr_pos); for CIRCA UPDATE ********* \n");
      packet = stream_dupcat(s, snlri, mpattr_pos);
      }
      else
      {
      zlog_debug (" ******** we added packet = stream_dup (s);; ********* for CIRCA UPDATE \n");
      packet = stream_dup (s);
    }
      bgp_packet_set_size (packet);
      bgp_packet_add (peer, packet);
      BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
      stream_reset (s);
      stream_reset (snlri);
      zlog_debug ("we finished building the update message including %ld prefixes to %ld" ,snumber_of_sent_prefix_counter,peer->as);
      return packet;
    }
  return NULL;
}

/* Make BGP update packet.  */
static struct stream *
bgp_update_packet (struct peer *peer, afi_t afi, safi_t safi)
{
  zlog_debug ("we are sending message to %ld" ,peer->as);
  int snumber_of_sent_prefix_counter = 0;
  struct stream *s;
  struct stream *snlri;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct stream *packet;
  struct bgp_node *rn = NULL;
  struct bgp_info *binfo = NULL;
  bgp_size_t total_attr_len = 0;
  unsigned long attrlen_pos = 0;
  int space_remaining = 0;
  int space_needed = 0;
  size_t mpattrlen_pos = 0;
  size_t mpattr_pos = 0;

  s = peer->work;
  stream_reset (s);
  snlri = peer->scratch;
  stream_reset (snlri);
  int first_prefix_in_list = 1;
  adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->update);

  while (adv)
    {
      assert (adv->rn);
      rn = adv->rn;
      adj = adv->adj;
      if (adv->binfo)
        binfo = adv->binfo;

      space_remaining = STREAM_CONCAT_REMAIN (s, snlri, STREAM_SIZE(s)) -
                        BGP_MAX_PACKET_SIZE_OVERFLOW;
      space_needed = BGP_NLRI_LENGTH + bgp_packet_mpattr_prefix_size (afi, safi, &rn->p);

      /* When remaining space can't include NLRI and it's length.  */
      if (space_remaining < space_needed)
  break;

      /* If packet is empty, set attribute. */
      if (stream_empty (s))
  {
    struct prefix_rd *prd = NULL;
    u_char *tag = NULL;
    struct peer *from = NULL;

    if (rn->prn)
      prd = (struct prefix_rd *) &rn->prn->p;
          if (binfo)
            {
              from = binfo->peer;
              if (binfo->extra)
                tag = binfo->extra->tag;
            }

    /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
     * one byte message type.
     */
    bgp_packet_set_marker (s, BGP_MSG_UPDATE);

    /* 2: withdrawn routes length */
    stream_putw (s, 0);

    /* 3: total attributes length - attrlen_pos stores the position */
    attrlen_pos = stream_get_endp (s);
    stream_putw (s, 0);

    /* 4: if there is MP_REACH_NLRI attribute, that should be the first
     * attribute, according to draft-ietf-idr-error-handling. Save the
     * position.
     */
    mpattr_pos = stream_get_endp(s);

    /* 5: Encode all the attributes, except MP_REACH_NLRI attr. */
    total_attr_len = bgp_packet_attribute (NULL, peer, s,
                                           adv->baa->attr,
                                                 ((afi == AFI_IP && safi == SAFI_UNICAST) ?
                                                  &rn->p : NULL),
                                                 afi, safi,
                                           from, prd, tag);
          space_remaining = STREAM_CONCAT_REMAIN (s, snlri, STREAM_SIZE(s)) -
                            BGP_MAX_PACKET_SIZE_OVERFLOW;
          space_needed = BGP_NLRI_LENGTH + bgp_packet_mpattr_prefix_size (afi, safi, &rn->p);;

          /* If the attributes alone do not leave any room for NLRI then
           * return */
          if (space_remaining < space_needed)
            {
              zlog_err ("%s cannot send UPDATE, the attributes do not leave "
                        "room for NLRI", peer->host);
              /* Flush the FIFO update queue */
              while (adv)
                adv = bgp_advertise_clean (peer, adv->adj, afi, safi);
              return NULL;
            } 

  }

      if (afi == AFI_IP && safi == SAFI_UNICAST)
  stream_put_prefix (s, &rn->p);
      else
  {
    /* Encode the prefix in MP_REACH_NLRI attribute */
    struct prefix_rd *prd = NULL;
    u_char *tag = NULL;

    if (rn->prn)
      prd = (struct prefix_rd *) &rn->prn->p;
    if (binfo && binfo->extra)
      tag = binfo->extra->tag;

    if (stream_empty(snlri))
      mpattrlen_pos = bgp_packet_mpattr_start(snlri, afi, safi,
                adv->baa->attr);
    bgp_packet_mpattr_prefix(snlri, afi, safi, &rn->p, prd, tag);
  }
    snumber_of_sent_prefix_counter = snumber_of_sent_prefix_counter +1;

      if (BGP_DEBUG (update, UPDATE_OUT))
        {
          char buf[INET6_BUFSIZ];

          zlog (peer->log, LOG_DEBUG, "%s send UPDATE %s/%d",
                peer->host,
                inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ),
                rn->p.prefixlen);
        }
      /* Synchnorize attribute.  */
      if (adj->attr)
  bgp_attr_unintern (&adj->attr);
      else
  peer->scount[afi][safi]++;

      adj->attr = bgp_attr_intern (adv->baa->attr);

      adv = bgp_advertise_clean (peer, adj, afi, safi);
    }

  if (! stream_empty (s))
    {
      if (!stream_empty(snlri))
  {
    bgp_packet_mpattr_end(snlri, mpattrlen_pos);
    total_attr_len += stream_get_endp(snlri);
  }

      /* set the total attribute length correctly */
      stream_putw_at (s, attrlen_pos, total_attr_len);

      if (!stream_empty(snlri))
  packet = stream_dupcat(s, snlri, mpattr_pos);
      else
  packet = stream_dup (s);
      bgp_packet_set_size (packet);
      bgp_packet_add (peer, packet);
      BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
      stream_reset (s);
      stream_reset (snlri);
      zlog_debug ("we finished building the update message including %ld prefixes to %ld" ,snumber_of_sent_prefix_counter,peer->as);
      return packet;
    }
  return NULL;
}

static struct stream *
bgp_update_packet_eor (struct peer *peer, afi_t afi, safi_t safi)
{
  struct stream *s;

  if (DISABLE_BGP_ANNOUNCE)
    return NULL;

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("send End-of-RIB for %s to %s", afi_safi_print (afi, safi), peer->host);

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_UPDATE);

  /* Unfeasible Routes Length */
  stream_putw (s, 0);

  if (afi == AFI_IP && safi == SAFI_UNICAST)
    {
      /* Total Path Attribute Length */
      stream_putw (s, 0);
    }
  else
    {
      /* Total Path Attribute Length */
      stream_putw (s, 6);
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_MP_UNREACH_NLRI);
      stream_putc (s, 3);
      stream_putw (s, afi);
      stream_putc (s, safi);
    }

  bgp_packet_set_size (s);
  bgp_packet_add (peer, s);
  return s;
}

int filling_data_structure_for_un_root_router(char root_cause_event_id[],char to_be_sent_time_stamp[],char * caused_time_stamp,char * prefix_value,struct peer * peer,int first_prefix_in_list)
{

  if (first_prefix_in_list==0)
    return 1;
  // zlog_debug(" we are going to fill unroot router data structure to send an update for  %s caused by %s",root_cause_event_id,caused_time_stamp);
  // print_caused_time_stamp_ds(&caused_time_stamps_head);
  struct caused_time_stamps * caused_time_stamps_instance = (struct caused_time_stamps *) malloc (sizeof(struct caused_time_stamps));
  caused_time_stamps_instance = get_time_stamp_ds(&caused_time_stamps_head,caused_time_stamp,root_cause_event_id);
  // zlog_debug(" +++++++++++++++++++++++++++++++++++++got list of peers  prefix %s from  to %s",prefix_value,peer->host);
  if(caused_time_stamps_instance !=NULL)
  {
    struct list_of_time_stamps * list_of_time_stamps_for_this;
    list_of_time_stamps_for_this = caused_time_stamps_instance -> generated_time_stamps ;
    // zlog_debug(" +++++++++++++++++++++++++++++++++++++we ar going to ge the list of time stamps  prefix %s being sent to %s",prefix_value,peer->host);
    while(list_of_time_stamps_for_this != NULL)
    {
      struct cause* cause_of_fizzle = (struct cause*) malloc(sizeof(struct cause));
      // zlog_debug(" +++++++++++++++++++++++++++++++++++++going to get cause  prefix %s from  to %s",prefix_value,peer->host);
      cause_of_fizzle = getcause(&(cause_head),list_of_time_stamps_for_this->time_stamp_id ,list_of_time_stamps_for_this->event_id);
      // zlog_debug(" +++++++++++++++++++++++++++++++++++++ got cause  prefix %s from  to %s",prefix_value,peer->host);
      if (cause_of_fizzle != NULL)

        if(strcmp(cause_of_fizzle->sending_timestamp,list_of_time_stamps_for_this->time_stamp_id)==0 && strcmp(list_of_time_stamps_for_this->send_to_peer->host,peer->host)==0 )
        {
          strncpy(root_cause_event_id,cause_of_fizzle->event_id,EVENT_ID_LENGTH);
          strncpy(to_be_sent_time_stamp,cause_of_fizzle->sending_timestamp,TIME_STAMP_LENGTH);
          // zlog_debug(" +++++++++++++++++++++++++++++++++++++we are setting %s as one time stamp generated by %s send to %s",to_be_sent_time_stamp,cause_of_fizzle->received_timestamp,peer->host);
          break;
        }
      list_of_time_stamps_for_this = list_of_time_stamps_for_this -> next;
    }

  add_to_sent(&sent_head, to_be_sent_time_stamp, root_cause_event_id,peer);
  /* add the peer as one of the neighbors we have sent event id to them(required for CDC third phase)*/
  //add_peer_to_neighbors_sent_to(&neighbours_sent_to_head, root_cause_event_id,peer);
  struct peer_list* appending_peer_list = NULL;
  struct neighbours_sent_to * the_neighbours_we_have_sent_event = (struct neighbours_sent_to *) malloc (sizeof(struct neighbours_sent_to));
  the_neighbours_we_have_sent_event = get_neighbours_sent_to(&(neighbours_sent_to_head),root_cause_event_id);
    if (the_neighbours_we_have_sent_event != NULL)
    {
        // zlog_debug (" Before adding to the list and neighbors of the prefix");
        // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));
        remove_neighbours_event_sent_to(&(neighbours_sent_to_head), root_cause_event_id);
        // zlog_debug (" after removing to the list and neighbors of the prefix");
        // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));
        struct peer_list * my_temp = the_neighbours_we_have_sent_event -> peer_list ;
        //zlog_debug("********** going to print the peer list ********");
        /* a variable which we will check if we have already have the peer in the list of peers we have sent them for this event */
        int already_sent =0;
        while(my_temp != NULL)
        {
            // zlog_debug("this is the host of the peer %s we are sending this update %s to", my_temp -> peer -> host,root_cause_event_id);
            //bgp_convergence_send (my_temp -> peer,rec_root_cause_event_id, received_prefix);
            add_to_peer_list(&(appending_peer_list), my_temp -> peer);
            if (my_temp -> peer->as==peer->as)
              already_sent=1;
            my_temp = my_temp -> next;
         }

        // zlog_debug("Lets add this new peer %s to the list too as a peer we are sending event %s to it",peer->host,root_cause_event_id);
        /* we will add the peer to the list of peers we have sent event update to them if we have not added before */
        if(already_sent==0)
        add_to_peer_list(&(appending_peer_list),  peer);
        // zlog_debug("We added to the list");
        add_to_neighbours_sent_to_of_an_event(&(neighbours_sent_to_head),root_cause_event_id, appending_peer_list);
        // zlog_debug("We added the list to the neighbor of the prefix data structure");
        // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));
    }
      else
      {
          // zlog_debug (" We have not sent  %s to any neighbor!!!", root_cause_event_id);
          struct peer_list* appending_peer_list2 = NULL;
          add_to_peer_list(&(appending_peer_list2),  peer);
          // zlog_debug("We added just this one to the list");
          add_to_neighbours_sent_to_of_an_event(&(neighbours_sent_to_head), root_cause_event_id, appending_peer_list2);
          //print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));

      }
    /* We will set this event id as an event which ha not convergence and if it has not been set before */
    insert_in_converged(&converged_head, root_cause_event_id);
    return 1;
  }
  else{
  //zlog_debug("+++++++++++++++++++++++++++++++++++++++We have received this prefix but we did not get any time tamp for it !!! %s",prefix_value);
  return -1;
  }
}


/* this function will fill the sent, cause data strucures for the event we are the owner */
void filling_data_structure_for_root_router(char root_cause_event_id[],char to_be_sent_time_stamp[],struct peer *peer,bool first_prefix_on_origin_list)
{
  if(!first_prefix_on_origin_list)
    return ;
  // zlog_debug("******+++++++++++++++++*******++++++++++++++++++++++ we are going to fill data structures for root router *********++++++++*******");
  // print_caused_time_stamp_ds(&caused_time_stamps_head);
  char * caused_time_stamp[TIME_STAMP_LENGTH];
  strncpy(caused_time_stamp ,"GRC", TIME_STAMP_LENGTH);
  /* we have already generated a new event id based on the event has accoured or received from ground*/
  //generate_global_event_id(peer->local_as,&root_cause_event_id);
  char global_e_id_value3[EVENT_ID_LENGTH];
  generate_global_event_id(peer->local_as,&global_e_id_value3);
  strncpy(root_cause_event_id,global_e_id_value3, TIME_STAMP_LENGTH);
  // zlog_debug("+1.1.1.+++++++++++++++++root router ++++++++++++++++++++++ the current event id being used is  %s",root_cause_event_id);
  char * local_time_stamp[TIME_STAMP_LENGTH];
  char * router_id[TIME_STAMP_LENGTH];
  sprintf(router_id, "%u", peer->local_as);
  generate_time_stamp(&local_time_stamp,router_id);
  
  // zlog_debug("we are adding time stamp ");
  strncpy(to_be_sent_time_stamp,local_time_stamp,TIME_STAMP_LENGTH);
  //zlog_debug("we generated %s ",to_be_sent_time_stamp);
 /* we add to sent and converged and also in cause */
        /* add to the sent data structure */
  // zlog_debug("we are adding  to_be_sent_time_stamp  %s and root_cause_event_id %s to sent to send to %s",to_be_sent_time_stamp,root_cause_event_id,peer->host);

  add_to_sent(&sent_head, to_be_sent_time_stamp, root_cause_event_id,peer);

  /* add the peer as one of the neighbors we have sent event id to them(required for CDC third phase)*/
  //add_peer_to_neighbors_sent_to(&neighbours_sent_to_head, root_cause_event_id,peer);
  struct peer_list* appending_peer_list = NULL;
  struct neighbours_sent_to * the_neighbours_we_have_sent_event = (struct neighbours_sent_to *) malloc (sizeof(struct neighbours_sent_to));
  the_neighbours_we_have_sent_event = get_neighbours_sent_to(&(neighbours_sent_to_head),root_cause_event_id);
    if (the_neighbours_we_have_sent_event != NULL)
    {
        // zlog_debug (" Before adding to the list and neighbors of the prefix");
        // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));
        remove_neighbours_event_sent_to(&(neighbours_sent_to_head), root_cause_event_id);
        // zlog_debug (" after removing to the list and neighbors of the prefix");
        // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));
        struct peer_list * my_temp = the_neighbours_we_have_sent_event -> peer_list ;
        //zlog_debug("********** going to print the peer list ********");
        /* a variable which we will check if we have already have the peer in the list of peers we have sent them for this event */
        int already_sent =0;
        while(my_temp != NULL)
        {
            // zlog_debug("this is the host of the peer %s we are sending this update %s to", my_temp -> peer -> host,root_cause_event_id);
            //bgp_convergence_send (my_temp -> peer,rec_root_cause_event_id, received_prefix);
            add_to_peer_list(&(appending_peer_list), my_temp -> peer);
            if (my_temp -> peer->as==peer->as)
              already_sent=1;
            my_temp = my_temp -> next;
         }

        // zlog_debug("Lets add this new peer %s to the list too as a peer we are sending event %s to it",peer->host,root_cause_event_id);
        /* we will add the peer to the list of peers we have sent event update to them if we have not added before */
        if(already_sent==0)
        add_to_peer_list(&(appending_peer_list),  peer);
        // zlog_debug("We added to the list");
        add_to_neighbours_sent_to_of_an_event(&(neighbours_sent_to_head),root_cause_event_id, appending_peer_list);
        // zlog_debug("We added the list to the neighbor of the prefix data structure");
        // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));
    }
      else
      {
          // zlog_debug (" We have not sent  %s to any neighbor!!!", root_cause_event_id);
          struct peer_list* appending_peer_list2 = NULL;
          add_to_peer_list(&(appending_peer_list2),  peer);
          // zlog_debug("We added just this one to the list");
          add_to_neighbours_sent_to_of_an_event(&(neighbours_sent_to_head), root_cause_event_id, appending_peer_list2);
          // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));

      }

  

    /* We will set this event id as an event which ha not convergence and if it has not been set before */
    insert_in_converged(&converged_head, root_cause_event_id);


}

/* Make CIRCA withdraw packet.  */
/* For ipv4 unicast:
   16-octet marker | 2-octet length | 1-octet type |
    2-octet withdrawn route length | withdrawn prefixes | 2-octet attrlen (=0)
*/
/* For other afi/safis:
   16-octet marker | 2-octet length | 1-octet type |
    2-octet withdrawn route length (=0) | 2-octet attrlen |
     mp_unreach attr type | attr len | afi | safi | withdrawn prefixes
*/
static struct stream *
circa_withdraw_packet (struct peer *peer, afi_t afi, safi_t safi,bool first_prefix_in_list)
{

  
  zlog_debug ("we are sending withdraw message to %ld" ,peer->as);
  int sent_prefix_in_withdraw_counter = 0;
  struct stream *s;
  struct stream *packet;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct bgp_node *rn;
  bgp_size_t unfeasible_len;
  bgp_size_t total_attr_len;
  size_t mp_start = 0;
  size_t attrlen_pos = 0;
  size_t mplen_pos = 0;
  u_char first_time = 1;
  int space_remaining = 0;
  int space_needed = 0;

  s = peer->work;
  stream_reset (s);
char buf2[INET6_BUFSIZ];
  while ((adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->withdraw)) != NULL)
    {
      assert (adv->rn);
      adj = adv->adj;
      rn = adv->rn;

      space_remaining = STREAM_REMAIN (s) -
                        BGP_MAX_PACKET_SIZE_OVERFLOW;
      space_needed = (BGP_NLRI_LENGTH + BGP_TOTAL_ATTR_LEN +
                      bgp_packet_mpattr_prefix_size (afi, safi, &rn->p));

      if (space_remaining < space_needed)
  break;
  
  //zlog_debug("we are going to send withdraw for prefix %s/%d to %s",inet_ntop (rn->p.family, &(rn->p.u.prefix), buf2, INET6_BUFSIZ), rn->p.prefixlen,peer->host);
  // struct bgp_advertise *adv;
  // adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->update);
  // if(strcmp("Static announcement",adv->binfo->peer->host)==0)
  // {
  //   zlog_debug ("************************\n");
  //   zlog_debug ("************************\n");
  //   zlog_debug ("************we are the owner of these prefixes************\n");
  //   zlog_debug ("************************\n");
  //   zlog_debug ("************************\n");
  // }
  // if(strcmp("Static announcement",adv->binfo->peer->host)!=0){
  //   zlog_debug ("************************\n");
  //   //zlog_debug ("***********the ASPATH is %s %s*************\n",adv->baa->attr->aspath->str,adv->baa->attr->nexthop.s_addr);
  //   zlog_debug ("************************\n");
  // }
  // zlog_debug("2 we are going to send withdraw for prefix %s/%d to %s",inet_ntop (rn->p.family, &(rn->p.u.prefix), buf2, INET6_BUFSIZ), rn->p.prefixlen,peer->host);

  /* here we will generate a new unique time stamp for our sending packet */
    char * caused_time_stamp[TIME_STAMP_LENGTH];
    char * root_cause_event_id[EVENT_ID_LENGTH];
    char * to_be_sent_time_stamp[TIME_STAMP_LENGTH];
    char * router_id[20];
    sprintf(router_id, "%u", peer->local_as);

    char as_path_str[50];
    strncpy(as_path_str,"withdraw",ASPATH_SIZE);
    struct peer * sender_peer_of_prefix = NULL;
    char * prefix_value[PREFIX_LENGTH];
    concat_prefix_length(inet_ntop (rn->p.family, &(rn->p.u.prefix), buf2, INET6_BUFSIZ),rn->p.prefixlen,prefix_value,PREFIX_LENGTH);

    if(check_if_we_have_received_prefix(&time_stamp_ds_head,prefix_value,0,as_path_str))
    {
        int ret;
        // zlog_debug(" go to get event id time stam");
       ret = get_event_id_time_stamp(&time_stamp_ds_head,prefix_value,0,&root_cause_event_id,&caused_time_stamp);
      // zlog_debug(" got event id time stam %s %s",root_cause_event_id,caused_time_stamp);
      // zlog_debug(" got event id time stam2 %s %s",root_cause_event_id,caused_time_stamp);
       if (ret >0)
       {
        // zlog_debug(" got event id time stam3 %s %s",root_cause_event_id,caused_time_stamp);

          //zlog_debug(" +++++++++++++++++++++++++++++++++++++lets get a time stamp we have generated for sending prefix %s from  to %s",prefix_value,peer->host);
          struct caused_time_stamps * caused_time_stamps_instance = (struct caused_time_stamps *) malloc (sizeof(struct caused_time_stamps));
           caused_time_stamps_instance =  get_time_stamp_ds(&caused_time_stamps_head,caused_time_stamp,root_cause_event_id);
          // zlog_debug(" +++++++++++++++++++++++++++++++++++++got list of peers  prefix %s from  to %s",prefix_value,peer->host);
           if(caused_time_stamps_instance !=NULL)
        {
            struct list_of_time_stamps * list_of_time_stamps_for_this;
            list_of_time_stamps_for_this = caused_time_stamps_instance -> generated_time_stamps ;
            bool we_got_time_stamp_event_id = false;
            // zlog_debug(" +++++++++++++++++++++++++++++++++++++setted list of time stamps  prefix %s from  to %s",prefix_value,peer->host);
            struct cause* cause_of_fizzle = (struct cause*) malloc(sizeof(struct cause));
            while(list_of_time_stamps_for_this != NULL)
                {
                // zlog_debug(" +++++++++++++++++++++++++++++++++++++going to get cause  prefix %s from  to %s",prefix_value,peer->host);
                cause_of_fizzle = getcause(&(cause_head),list_of_time_stamps_for_this->time_stamp_id ,list_of_time_stamps_for_this->event_id);
                // zlog_debug(" +++++++++++++++++++++++++++++++++++++ got cause  prefix %s from  to %s",prefix_value,peer->host);

                if (cause_of_fizzle != NULL)
                  if(strcmp(cause_of_fizzle->sending_timestamp,list_of_time_stamps_for_this->time_stamp_id)==0)
                  {
                    strncpy(root_cause_event_id,cause_of_fizzle->event_id,EVENT_ID_LENGTH);
                    strncpy(to_be_sent_time_stamp,cause_of_fizzle->sending_timestamp,TIME_STAMP_LENGTH);
                    // zlog_debug(" +++++++++++++++++++++++++++++++++++++we are setting %s as one time stamp generated by %s send to %s",to_be_sent_time_stamp,cause_of_fizzle->received_timestamp,peer->host);
                    we_got_time_stamp_event_id = true;
                    break;
                  }
                  list_of_time_stamps_for_this = list_of_time_stamps_for_this -> next;
                 }

        if(we_got_time_stamp_event_id)
        {
          int ret2;
          ret2 = filling_data_structure_for_un_root_router(&root_cause_event_id,&to_be_sent_time_stamp,cause_of_fizzle->received_timestamp,prefix_value,peer,first_prefix_in_list);
          first_prefix_in_list = false;
          if(ret2<0)
          {
            filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_in_list);
            first_prefix_in_list = false;
          }
        }
        else
        {
          filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_in_list);
          first_prefix_in_list = false;
        }

        }
        else{
          // zlog_debug("++++++++++++++++++++withdraw+++++++++++++++++++We have received this prefix but we did not get any time tamp for it !!! %s",prefix_value);
          filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_in_list);
          first_prefix_in_list = false;
          // zlog_debug("******+++++++++++++++++*******++++++++++++++++++++++ we did fill data structures for root router to_be_sent_time_stamp %s  and root_cause_event_id %s *********++++++++*******",to_be_sent_time_stamp,root_cause_event_id);
        }
       }
       else{
          // zlog_debug("+++++++++++++++22+++withdraw+++++++++++++++++++++We have received this prefix but we did not get any time tamp for it !!! %s",prefix_value);
          filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_in_list);
          first_prefix_in_list = false;
          // zlog_debug("******+++++++++++++++++*******++++++++++++++++++++++ we did fill data structures for root router to_be_sent_time_stamp %s  and root_cause_event_id %s *********++++++++*******",to_be_sent_time_stamp,root_cause_event_id);
       }


    }
    else
      {
        // zlog_debug("+1+++++++++++++++++++++withdraw++++++++++++++++++We have not received this prefix or we have received but in converged events %s",prefix_value);
        // zlog_debug("++++++++++++++++++++++++++withdraw++++++++++++++We will get event id from GRC message");
        // zlog_debug("++++++++++++++++++++++withdraw++++++++++++++++++We will get event id from GRC message");
        filling_data_structure_for_root_router(&root_cause_event_id,&to_be_sent_time_stamp,peer,first_prefix_in_list);
        first_prefix_in_list = false;
        // zlog_debug("******+++++++++++++++++*******++++++++++++++++++++++ we did fill data structures for root router to_be_sent_time_stamp %s  and root_cause_event_id %s *********++++++++*******",to_be_sent_time_stamp,root_cause_event_id);
      }


/* end of getting or generating event id and time stamps */



      if (stream_empty (s))
  {
    bgp_packet_set_marker (s, CIRCA_MSG_UPDATE);

    /* we add our CIRCA system related fields here */
    long router_id_value;
    char *backup_event_id[EVENT_ID_LENGTH];
    // if (peer->local_as>3)
    //   strncpy(root_cause_event_id,"7643,5",EVENT_ID_LENGTH);
    // if (peer->local_as<5)
    // strncpy(root_cause_event_id,"7643,3",EVENT_ID_LENGTH);
    strncpy(backup_event_id,root_cause_event_id,EVENT_ID_LENGTH);

    router_id_value = str_split(backup_event_id, ',',1);
    long seq_number_sec = str_split(backup_event_id, ',',0);
    /* add CBGP sybtype */
    // zlog_debug("we are sending %ld as CIRCA_MSG_UPDATE(withdraw) to %s",CIRCA_MSG_UPDATE,peer->host);
    stream_putl (s, CIRCA_MSG_UPDATE);
    /* add root cause event id */
    // zlog_debug("we are sending %s as event id to %s",backup_event_id,peer->host);

    // zlog_debug("we are sending %ld as seq_number_sec_of_event_id to %s %s",seq_number_sec,peer->host,root_cause_event_id);

    stream_putl (s, seq_number_sec);
    // zlog_debug("we are sending %ld as  router_id_value_of_event id to %s %s",router_id_value,peer->host,root_cause_event_id);
    stream_putl (s, router_id_value);
    /* add time stamp */
    long router_value_in_time_stamp;
    char backup_time_stam[TIME_STAMP_LENGTH];

    strncpy(backup_time_stam,to_be_sent_time_stamp,TIME_STAMP_LENGTH);

    router_value_in_time_stamp = str_split(backup_time_stam, ',',1);
    // zlog_debug("this is our time stamp after getting router value of it  %s  ",to_be_sent_time_stamp);
    long seq_number_part_of_time_stamp = str_split(backup_time_stam, ',',0);
    // zlog_debug("we are sending %ld as seq_number_part_of_time_stamp  to %s %s",seq_number_part_of_time_stamp,peer->host,to_be_sent_time_stamp);

    stream_putl (s, seq_number_part_of_time_stamp);
    // zlog_debug("we are sending %ld as  router_value_in_time_stamp to %s %s",router_value_in_time_stamp,peer->host,to_be_sent_time_stamp);

    stream_putl (s, router_value_in_time_stamp);

    stream_putw (s, 0); /* unfeasible routes length */
  }
      else
  first_time = 0;

      if (afi == AFI_IP && safi == SAFI_UNICAST)
  stream_put_prefix (s, &rn->p);
      else
  {
    struct prefix_rd *prd = NULL;

    if (rn->prn)
      prd = (struct prefix_rd *) &rn->prn->p;

    /* If first time, format the MP_UNREACH header */
    if (first_time)
      {
        attrlen_pos = stream_get_endp (s);
        // zlog_debug("If first time, format the MP_UNREACH header attrlen_pos is %ld",attrlen_pos);
        /* total attr length = 0 for now. reevaluate later */
        stream_putw (s, 0);
        mp_start = stream_get_endp (s);
        // zlog_debug("If first time, format the mp_start is %ld",mp_start);

        mplen_pos = bgp_packet_mpunreach_start(s, afi, safi);
      }

    bgp_packet_mpunreach_prefix(s, &rn->p, afi, safi, prd, NULL);
  }
  sent_prefix_in_withdraw_counter = sent_prefix_in_withdraw_counter +1;

      if (BGP_DEBUG (update, UPDATE_OUT))
        {
          char buf[INET6_BUFSIZ];

          zlog (peer->log, LOG_DEBUG, "%s send UPDATE %s/%d -- unreachable(circa_withdraw_packet)",
                peer->host,
                inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ),
                rn->p.prefixlen);
        }

      peer->scount[afi][safi]--;

      bgp_adj_out_remove (rn, adj, peer, afi, safi);
      bgp_unlock_node (rn);
    }

  if (! stream_empty (s))
    {
      if (afi == AFI_IP && safi == SAFI_UNICAST)
  {
    unfeasible_len
      = stream_get_endp (s) - BGP_HEADER_SIZE - BGP_UNFEASIBLE_LEN-20;
    // zlog_debug("the unfeasible_len  is %ld",unfeasible_len);

    stream_putw_at (s, BGP_HEADER_SIZE+20, unfeasible_len);


    stream_putw (s, 0);
  }
      else
  {
    /* Set the mp_unreach attr's length */
    bgp_packet_mpunreach_end(s, mplen_pos);

    /* Set total path attribute length. */
    total_attr_len = stream_get_endp(s) - mp_start;
    // zlog_debug(" Set total path attribute length is %ld at %ld",total_attr_len,attrlen_pos);

    stream_putw_at (s, attrlen_pos, total_attr_len);
  }
      bgp_packet_set_size (s);
      packet = stream_dup (s);
      bgp_packet_add (peer, packet);
      stream_reset (s);
      zlog_debug ("we finished building the withdraw message with %ld prefixes be sent to %ld" ,sent_prefix_in_withdraw_counter,peer->as);

      return packet;
    }

  return NULL;
}


/* Make BGP withdraw packet.  */
/* For ipv4 unicast:
   16-octet marker | 2-octet length | 1-octet type |
    2-octet withdrawn route length | withdrawn prefixes | 2-octet attrlen (=0)
*/
/* For other afi/safis:
   16-octet marker | 2-octet length | 1-octet type |
    2-octet withdrawn route length (=0) | 2-octet attrlen |
     mp_unreach attr type | attr len | afi | safi | withdrawn prefixes
*/
static struct stream *
bgp_withdraw_packet (struct peer *peer, afi_t afi, safi_t safi)
{
  zlog_debug ("we are sending withdraw message to %ld" ,peer->as);

  struct stream *s;
  struct stream *packet;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct bgp_node *rn;
  bgp_size_t unfeasible_len;
  bgp_size_t total_attr_len;
  size_t mp_start = 0;
  size_t attrlen_pos = 0;
  size_t mplen_pos = 0;
  u_char first_time = 1;
  int space_remaining = 0;
  int space_needed = 0;
  int sent_prefix_in_withdraw_counter = 0;

  s = peer->work;
  stream_reset (s);
char buf2[INET6_BUFSIZ];
  while ((adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->withdraw)) != NULL)
    {
      assert (adv->rn);
      adj = adv->adj;
      rn = adv->rn;

      space_remaining = STREAM_REMAIN (s) -
                        BGP_MAX_PACKET_SIZE_OVERFLOW;
      space_needed = (BGP_NLRI_LENGTH + BGP_TOTAL_ATTR_LEN +
                      bgp_packet_mpattr_prefix_size (afi, safi, &rn->p));

      if (space_remaining < space_needed)
  break;
  //zlog_debug("we are going to send withdraw for prefix %s/%d to %s",inet_ntop (rn->p.family, &(rn->p.u.prefix), buf2, INET6_BUFSIZ), rn->p.prefixlen,peer->host);

  // if(check_if_we_have_received_withdra(inet_ntop (rn->p.family, &(rn->p.u.prefix), buf2, INET6_BUFSIZ)))
  // {
  //   get_time_stamp();
  //   add_to_sent();
  //   addcause();
  //   insert_in_converged();

  // }
  // if(!check_if_we_have_received_withdra(inet_ntop (rn->p.family, &(rn->p.u.prefix), buf2, INET6_BUFSIZ)))
  // {
  //   generate_time_stamp()
  //   add_to_sent();
  //   addcause();
  //   insert_in_converged();
  // }


      if (stream_empty (s))
  {
    bgp_packet_set_marker (s, BGP_MSG_UPDATE);
    stream_putw (s, 0); /* unfeasible routes length */
  }
      else
  first_time = 0;

      if (afi == AFI_IP && safi == SAFI_UNICAST)
  stream_put_prefix (s, &rn->p);
      else
  {
    struct prefix_rd *prd = NULL;

    if (rn->prn)
      prd = (struct prefix_rd *) &rn->prn->p;

    /* If first time, format the MP_UNREACH header */
    if (first_time)
      {
        attrlen_pos = stream_get_endp (s);
        // zlog_debug("If first time, format the MP_UNREACH header attrlen_pos is %ld",attrlen_pos);

        /* total attr length = 0 for now. reevaluate later */
        stream_putw (s, 0);
        mp_start = stream_get_endp (s);
        // zlog_debug("If first time, format the mp_start is %ld",mp_start);

        mplen_pos = bgp_packet_mpunreach_start(s, afi, safi);
      }

    bgp_packet_mpunreach_prefix(s, &rn->p, afi, safi, prd, NULL);
  }
  sent_prefix_in_withdraw_counter = sent_prefix_in_withdraw_counter +1;

      if (BGP_DEBUG (update, UPDATE_OUT))
        {
          char buf[INET6_BUFSIZ];

          zlog (peer->log, LOG_DEBUG, "%s send UPDATE %s/%d -- unreachable(bgp_withdraw_packet)",
                peer->host,
                inet_ntop (rn->p.family, &(rn->p.u.prefix), buf, INET6_BUFSIZ),
                rn->p.prefixlen);
        }

      peer->scount[afi][safi]--;

      bgp_adj_out_remove (rn, adj, peer, afi, safi);
      bgp_unlock_node (rn);
    }

  if (! stream_empty (s))
    {
      if (afi == AFI_IP && safi == SAFI_UNICAST)
  {
    unfeasible_len
      = stream_get_endp (s) - BGP_HEADER_SIZE - BGP_UNFEASIBLE_LEN;
    zlog_debug("the unfeasible_len  is %ld",unfeasible_len);

    stream_putw_at (s, BGP_HEADER_SIZE, unfeasible_len);
    stream_putw (s, 0);
  }
      else
  {
    /* Set the mp_unreach attr's length */
    bgp_packet_mpunreach_end(s, mplen_pos);

    /* Set total path attribute length. */
    total_attr_len = stream_get_endp(s) - mp_start;
    zlog_debug(" Set total path attribute length is %ld at %ld",total_attr_len,attrlen_pos);

    stream_putw_at (s, attrlen_pos, total_attr_len);
  }
      bgp_packet_set_size (s);
      packet = stream_dup (s);
      bgp_packet_add (peer, packet);
      stream_reset (s);
      zlog_debug ("we finished building the withdraw message with %ld prefixes be sent to %ld" ,sent_prefix_in_withdraw_counter,peer->as);

      return packet;
    }

  return NULL;
}

void
bgp_default_update_send (struct peer *peer, struct attr *attr,
       afi_t afi, safi_t safi, struct peer *from)
{
  struct stream *s;
  struct prefix p;
  unsigned long pos;
  bgp_size_t total_attr_len;

  if (DISABLE_BGP_ANNOUNCE)
    return;

  if (afi == AFI_IP)
    str2prefix ("0.0.0.0/0", &p);
  else 
    str2prefix ("::/0", &p);

  /* Logging the attribute. */
  if (BGP_DEBUG (update, UPDATE_OUT))
    {
      char attrstr[BUFSIZ];
      char buf[INET6_BUFSIZ];
      attrstr[0] = '\0';

      bgp_dump_attr (peer, attr, attrstr, BUFSIZ);
      zlog (peer->log, LOG_DEBUG, "%s send UPDATE %s/%d %s",
      peer->host, inet_ntop(p.family, &(p.u.prefix), buf, INET6_BUFSIZ),
      p.prefixlen, attrstr);
    }

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_UPDATE);

  /* Unfeasible Routes Length. */
  stream_putw (s, 0);

  /* Make place for total attribute length.  */
  pos = stream_get_endp (s);
  stream_putw (s, 0);
  total_attr_len = bgp_packet_attribute (NULL, peer, s, attr, &p, afi, safi, from, NULL, NULL);

  /* Set Total Path Attribute Length. */
  stream_putw_at (s, pos, total_attr_len);

  /* NLRI set. */
  if (p.family == AF_INET && safi == SAFI_UNICAST)
    stream_put_prefix (s, &p);

  /* Set size. */
  bgp_packet_set_size (s);

  /* Dump packet if debug option is set. */
#ifdef DEBUG
  /* bgp_packet_dump (packet); */
#endif /* DEBUG */

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

void
bgp_default_withdraw_send (struct peer *peer, afi_t afi, safi_t safi)
{
  struct stream *s;
  struct prefix p;
  unsigned long attrlen_pos = 0;
  unsigned long cp;
  bgp_size_t unfeasible_len;
  bgp_size_t total_attr_len;
  size_t mp_start = 0;
  size_t mplen_pos = 0;

  if (DISABLE_BGP_ANNOUNCE)
    return;

  if (afi == AFI_IP)
    str2prefix ("0.0.0.0/0", &p);
  else 
    str2prefix ("::/0", &p);

  total_attr_len = 0;

  if (BGP_DEBUG (update, UPDATE_OUT))
    {
      char buf[INET6_BUFSIZ];

      zlog (peer->log, LOG_DEBUG, "%s send UPDATE %s/%d -- unreachable(bgp_default_withdraw_send)",
            peer->host, inet_ntop(p.family, &(p.u.prefix), buf, INET6_BUFSIZ),
            p.prefixlen);
    }

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_UPDATE);

  /* Unfeasible Routes Length. */;
  cp = stream_get_endp (s);
  stream_putw (s, 0);

  /* Withdrawn Routes. */
  if (p.family == AF_INET && safi == SAFI_UNICAST)
    {
      stream_put_prefix (s, &p);

      unfeasible_len = stream_get_endp (s) - cp - 2;

      /* Set unfeasible len.  */
      stream_putw_at (s, cp, unfeasible_len);

      /* Set total path attribute length. */
      stream_putw (s, 0);
    }
  else
    {
      attrlen_pos = stream_get_endp (s);
      stream_putw (s, 0);
      mp_start = stream_get_endp (s);
      mplen_pos = bgp_packet_mpunreach_start(s, afi, safi);
      bgp_packet_mpunreach_prefix(s, &p, afi, safi, NULL, NULL);

      /* Set the mp_unreach attr's length */
      bgp_packet_mpunreach_end(s, mplen_pos);

      /* Set total path attribute length. */
      total_attr_len = stream_get_endp(s) - mp_start;
      stream_putw_at (s, attrlen_pos, total_attr_len);
    }

  bgp_packet_set_size (s);

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Get next packet to be written.  */
static struct stream *
bgp_write_packet (struct peer *peer)
{
  afi_t afi;
  safi_t safi;
  struct stream *s = NULL;
  struct bgp_advertise *adv;

  s = stream_fifo_head (peer->obuf);
  if (s)
    return s;
  bool first_prefix_in_list = true;
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      {
  adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->withdraw);
  if (adv)
    {
      if(working_mode==0)
        s = bgp_withdraw_packet (peer, afi, safi);
      if(working_mode==1)
      {
        s = circa_withdraw_packet (peer, afi, safi,first_prefix_in_list);
        first_prefix_in_list = false;
      }

      if (s)
        return s;
    }
      }
    
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      {
  adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->update);
  if (adv)
    {
            if (adv->binfo && adv->binfo->uptime <= peer->synctime)
        {
    if (CHECK_FLAG (adv->binfo->peer->cap, PEER_CAP_RESTART_RCV)
        && CHECK_FLAG (adv->binfo->peer->cap, PEER_CAP_RESTART_ADV)
        && ! (CHECK_FLAG (adv->binfo->peer->cap,
                                      PEER_CAP_RESTART_BIT_RCV) &&
              CHECK_FLAG (adv->binfo->peer->cap,
                                      PEER_CAP_RESTART_BIT_ADV))
        && ! CHECK_FLAG (adv->binfo->flags, BGP_INFO_STALE)
        && safi != SAFI_MPLS_VPN)
      {
        if (CHECK_FLAG (adv->binfo->peer->af_sflags[afi][safi],
      PEER_STATUS_EOR_RECEIVED))
        {
          if (working_mode ==1)
          s =  circa_update_packet(peer, afi, safi);
          if (working_mode ==0)
          s = bgp_update_packet (peer, afi, safi);
        }
      }
    else
    {
        if (working_mode ==1)
          s =  circa_update_packet(peer, afi, safi);
        if (working_mode ==0)
          s = bgp_update_packet (peer, afi, safi);
    }
        }

      if (s)
        return s;
    }

  if (CHECK_FLAG (peer->cap, PEER_CAP_RESTART_RCV))
    {
      if (peer->afc_nego[afi][safi] && peer->synctime
    && ! CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_EOR_SEND)
    && safi != SAFI_MPLS_VPN)
        {
    SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_EOR_SEND);
    return bgp_update_packet_eor (peer, afi, safi);
        }
    }
      }

  return NULL;
}

/* Is there partially written packet or updates we can send right
   now.  */
static int
bgp_write_proceed (struct peer *peer)
{
  afi_t afi;
  safi_t safi;
  struct bgp_advertise *adv;

  if (stream_fifo_head (peer->obuf))
    return 1;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      if (FIFO_HEAD (&peer->sync[afi][safi]->withdraw))
  return 1;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      if ((adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->update)) != NULL)
  if (adv->binfo->uptime <= peer->synctime)
    return 1;

  return 0;
}

/* Write packet to the peer. */
int
bgp_write (struct thread *thread)
{
  struct peer *peer;
  u_char type;
  struct stream *s; 
  int num;
  unsigned int count = 0;

  /* Yes first of all get peer pointer. */
  peer = THREAD_ARG (thread);
  peer->t_write = NULL;

  /* For non-blocking IO check. */
  if (peer->status == Connect)
    {
      bgp_connect_check (peer);
      return 0;
    }

  s = bgp_write_packet (peer);
  if (!s)
    return 0; /* nothing to send */

  sockopt_cork (peer->fd, 1);

  /* Nonblocking write until TCP output buffer is full.  */
  do
    {
      int writenum;

      /* Number of bytes to be sent.  */
      writenum = stream_get_endp (s) - stream_get_getp (s);

      /* Call write() system call.  */
      num = write (peer->fd, STREAM_PNT (s), writenum);
      if (num < 0)
  {
    /* write failed either retry needed or error */
    if (ERRNO_IO_RETRY(errno))
    break;

          BGP_EVENT_ADD (peer, TCP_fatal_error);
    return 0;
  }

      if (num != writenum)
  {
    /* Partial write */
    stream_forward_getp (s, num);
    break;
  }

      /* Retrieve BGP packet type. */
      stream_set_getp (s, BGP_MARKER_SIZE + 2);
      type = stream_getc (s);

      switch (type)
  {
  case BGP_MSG_OPEN:
    peer->open_out++;
    break;
  case BGP_MSG_UPDATE:
    peer->update_out++;
    break;
  case BGP_MSG_NOTIFY:
    peer->notify_out++;

    /* Flush any existing events */
    BGP_EVENT_ADD (peer, BGP_Stop_with_error);
    goto done;

  case BGP_MSG_KEEPALIVE:
    peer->keepalive_out++;
    break;
  case BGP_MSG_ROUTE_REFRESH_NEW:
  case BGP_MSG_ROUTE_REFRESH_OLD:
    peer->refresh_out++;
    break;
  case BGP_MSG_CAPABILITY:
    peer->dynamic_cap_out++;
    break;
  }

      /* OK we send packet so delete it. */
      bgp_packet_delete (peer);
    }
  while (++count < BGP_WRITE_PACKET_MAX &&
   (s = bgp_write_packet (peer)) != NULL);
  
  if (bgp_write_proceed (peer))
    BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
  switch (type)
    {
    case BGP_MSG_UPDATE:
      zlog_debug ("*******...we wrote %ld update messages to socket for %ld",peer->update_out,peer->as);
    }
 done:
  sockopt_cork (peer->fd, 0);
  return 0;
}

/* This is only for sending NOTIFICATION message to neighbor. */
static int
bgp_write_notify (struct peer *peer)
{
  int ret, val;
  u_char type;
  struct stream *s; 

  /* There should be at least one packet. */
  s = stream_fifo_head (peer->obuf);
  if (!s)
    return 0;
  assert (stream_get_endp (s) >= BGP_HEADER_SIZE);

  /* Stop collecting data within the socket */
  sockopt_cork (peer->fd, 0);

  /* socket is in nonblocking mode, if we can't deliver the NOTIFY, well,
   * we only care about getting a clean shutdown at this point. */
  ret = write (peer->fd, STREAM_DATA (s), stream_get_endp (s));

  /* only connection reset/close gets counted as TCP_fatal_error, failure
   * to write the entire NOTIFY doesn't get different FSM treatment */
  if (ret <= 0)
    {
      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return 0;
    }

  /* Disable Nagle, make NOTIFY packet go out right away */
  val = 1;
  (void) setsockopt (peer->fd, IPPROTO_TCP, TCP_NODELAY,
                            (char *) &val, sizeof (val));

  /* Retrieve BGP packet type. */
  stream_set_getp (s, BGP_MARKER_SIZE + 2);
  type = stream_getc (s);

  assert (type == BGP_MSG_NOTIFY);

  /* Type should be notify. */
  peer->notify_out++;

  BGP_EVENT_ADD (peer, BGP_Stop_with_error);

  return 0;
}

/* Make keepalive packet and send it to the peer. */
void
bgp_keepalive_send (struct peer *peer)
{
  struct stream *s;
  int length;

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make keepalive packet. */
  bgp_packet_set_marker (s, BGP_MSG_KEEPALIVE);

  /* Set packet size. */
  length = bgp_packet_set_size (s);

  /* Dump packet if debug option is set. */
  /* bgp_packet_dump (s); */
 
  if (BGP_DEBUG (keepalive, KEEPALIVE))  
    zlog_debug ("%s sending KEEPALIVE", peer->host); 
  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s send message type %d, length (incl. header) %d",
               peer->host, BGP_MSG_KEEPALIVE, length);

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Make open packet and send it to the peer. */
void
bgp_open_send (struct peer *peer)
{
  struct stream *s;
  int length;
  u_int16_t send_holdtime;
  as_t local_as;

  if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
    send_holdtime = peer->holdtime;
  else
    send_holdtime = peer->bgp->default_holdtime;

  /* local-as Change */
  if (peer->change_local_as)
    local_as = peer->change_local_as; 
  else
    local_as = peer->local_as; 

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make open packet. */
  bgp_packet_set_marker (s, BGP_MSG_OPEN);

  /* Set open packet values. */
  stream_putc (s, BGP_VERSION_4);        /* BGP version */
  stream_putw (s, (local_as <= BGP_AS_MAX) ? (u_int16_t) local_as 
                                           : BGP_AS_TRANS);
  stream_putw (s, send_holdtime);        /* Hold Time */
  stream_put_in_addr (s, &peer->local_id); /* BGP Identifier */

  /* Set capability code. */
  bgp_open_capability (s, peer);

  /* Set BGP packet length. */
  length = bgp_packet_set_size (s);

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s sending OPEN, version %d, my as %u, holdtime %d, id %s", 
         peer->host, BGP_VERSION_4, local_as,
         send_holdtime, inet_ntoa (peer->local_id));

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s send message type %d, length (incl. header) %d",
         peer->host, BGP_MSG_OPEN, length);

  /* Dump packet if debug option is set. */
  /* bgp_packet_dump (s); */

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Send BGP notify packet with data potion. */
void
bgp_notify_send_with_data (struct peer *peer, u_char code, u_char sub_code,
         u_char *data, size_t datalen)
{
  struct stream *s;
  int length;

  /* Allocate new stream. */
  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make nitify packet. */
  bgp_packet_set_marker (s, BGP_MSG_NOTIFY);

  /* Set notify packet values. */
  stream_putc (s, code);        /* BGP notify code */
  stream_putc (s, sub_code);  /* BGP notify sub_code */

  /* If notify data is present. */
  if (data)
    stream_write (s, data, datalen);
  
  /* Set BGP packet length. */
  length = bgp_packet_set_size (s);
  
  /* Add packet to the peer. */
  stream_fifo_clean (peer->obuf);
  bgp_packet_add (peer, s);

  /* For debug */
  {
    struct bgp_notify bgp_notify;
    int first = 0;
    int i;
    char c[4];

    bgp_notify.code = code;
    bgp_notify.subcode = sub_code;
    bgp_notify.data = NULL;
    bgp_notify.length = length - BGP_MSG_NOTIFY_MIN_SIZE;
    
    if (bgp_notify.length)
      {
  bgp_notify.data = XMALLOC (MTYPE_TMP, bgp_notify.length * 3);
  for (i = 0; i < bgp_notify.length; i++)
    if (first)
      {
        sprintf (c, " %02x", data[i]);
        strcat (bgp_notify.data, c);
      }
    else
      {
        first = 1;
        sprintf (c, "%02x", data[i]);
        strcpy (bgp_notify.data, c);
      }
      }
    bgp_notify_print (peer, &bgp_notify, "sending");

    if (bgp_notify.data)
      {
        XFREE (MTYPE_TMP, bgp_notify.data);
        bgp_notify.data = NULL;
        bgp_notify.length = 0;
      }
  }

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s send message type %d, length (incl. header) %d",
         peer->host, BGP_MSG_NOTIFY, length);

  /* peer reset cause */
  if (sub_code != BGP_NOTIFY_CEASE_CONFIG_CHANGE)
    {
      if (sub_code == BGP_NOTIFY_CEASE_ADMIN_RESET)
      {
        peer->last_reset = PEER_DOWN_USER_RESET;
        zlog_info ("Notification sent to neighbor %s:%u: User reset",
                   peer->host, sockunion_get_port (&peer->su));
      }
      else if (sub_code == BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN)
      {
        peer->last_reset = PEER_DOWN_USER_SHUTDOWN;
        zlog_info ("Notification sent to neighbor %s:%u shutdown",
                    peer->host, sockunion_get_port (&peer->su));
      }
      else
      {
        peer->last_reset = PEER_DOWN_NOTIFY_SEND;
        zlog_info ("Notification sent to neighbor %s:%u: type %u/%u",
                   peer->host, sockunion_get_port (&peer->su),
                   code, sub_code);
      }
    }
  else
     zlog_info ("Notification sent to neighbor %s:%u: configuration change",
                peer->host, sockunion_get_port (&peer->su));

  /* Call immediately. */
  BGP_WRITE_OFF (peer->t_write);

  bgp_write_notify (peer);
}

/* Send BGP notify packet. */
void
bgp_notify_send (struct peer *peer, u_char code, u_char sub_code)
{
  bgp_notify_send_with_data (peer, code, sub_code, NULL, 0);
}

/* Send route refresh message to the peer. */
void
bgp_route_refresh_send (struct peer *peer, afi_t afi, safi_t safi,
      u_char orf_type, u_char when_to_refresh, int remove)
{
  struct stream *s;
  int length;
  struct bgp_filter *filter;
  int orf_refresh = 0;

  if (DISABLE_BGP_ANNOUNCE)
    return;

  filter = &peer->filter[afi][safi];

  /* Adjust safi code. */
  if (safi == SAFI_MPLS_VPN)
    safi = SAFI_MPLS_LABELED_VPN;
  
  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  if (CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV))
    bgp_packet_set_marker (s, BGP_MSG_ROUTE_REFRESH_NEW);
  else
    bgp_packet_set_marker (s, BGP_MSG_ROUTE_REFRESH_OLD);

  /* Encode Route Refresh message. */
  stream_putw (s, afi);
  stream_putc (s, 0);
  stream_putc (s, safi);
 
  if (orf_type == ORF_TYPE_PREFIX
      || orf_type == ORF_TYPE_PREFIX_OLD)
    if (remove || filter->plist[FILTER_IN].plist)
      {
  u_int16_t orf_len;
  unsigned long orfp;

  orf_refresh = 1; 
  stream_putc (s, when_to_refresh);
  stream_putc (s, orf_type);
  orfp = stream_get_endp (s);
  stream_putw (s, 0);

  if (remove)
    {
      UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_ORF_PREFIX_SEND);
      stream_putc (s, ORF_COMMON_PART_REMOVE_ALL);
      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s sending REFRESH_REQ to remove ORF(%d) (%s) for afi/safi: %d/%d", 
       peer->host, orf_type,
       (when_to_refresh == REFRESH_DEFER ? "defer" : "immediate"),
       afi, safi);
    }
  else
    {
      SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_ORF_PREFIX_SEND);
      prefix_bgp_orf_entry (s, filter->plist[FILTER_IN].plist,
          ORF_COMMON_PART_ADD, ORF_COMMON_PART_PERMIT,
          ORF_COMMON_PART_DENY);
      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s sending REFRESH_REQ with pfxlist ORF(%d) (%s) for afi/safi: %d/%d", 
       peer->host, orf_type,
       (when_to_refresh == REFRESH_DEFER ? "defer" : "immediate"),
       afi, safi);
    }

  /* Total ORF Entry Len. */
  orf_len = stream_get_endp (s) - orfp - 2;
  stream_putw_at (s, orfp, orf_len);
      }

  /* Set packet size. */
  length = bgp_packet_set_size (s);

  if (BGP_DEBUG (normal, NORMAL))
    {
      if (! orf_refresh)
  zlog_debug ("%s sending REFRESH_REQ for afi/safi: %d/%d", 
       peer->host, afi, safi);
      zlog_debug ("%s send message type %d, length (incl. header) %d",
     peer->host, CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV) ?
     BGP_MSG_ROUTE_REFRESH_NEW : BGP_MSG_ROUTE_REFRESH_OLD, length);
    }

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Send capability message to the peer. */
void
bgp_capability_send (struct peer *peer, afi_t afi, safi_t safi,
         int capability_code, int action)
{
  struct stream *s;
  int length;

  /* Adjust safi code. */
  if (safi == SAFI_MPLS_VPN)
    safi = SAFI_MPLS_LABELED_VPN;

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_CAPABILITY);

  /* Encode MP_EXT capability. */
  if (capability_code == CAPABILITY_CODE_MP)
    {
      stream_putc (s, action);
      stream_putc (s, CAPABILITY_CODE_MP);
      stream_putc (s, CAPABILITY_CODE_MP_LEN);
      stream_putw (s, afi);
      stream_putc (s, 0);
      stream_putc (s, safi);

      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s sending CAPABILITY has %s MP_EXT CAP for afi/safi: %d/%d",
       peer->host, action == CAPABILITY_ACTION_SET ?
       "Advertising" : "Removing", afi, safi);
    }

  /* Set packet size. */
  length = bgp_packet_set_size (s);


  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s send message type %d, length (incl. header) %d",
         peer->host, BGP_MSG_CAPABILITY, length);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* RFC1771 6.8 Connection collision detection. */
static int
bgp_collision_detect (struct peer *new, struct in_addr remote_id)
{
  struct peer *peer;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  bgp = bgp_get_default ();
  if (! bgp)
    return 0;
  
  /* Upon receipt of an OPEN message, the local system must examine
     all of its connections that are in the OpenConfirm state.  A BGP
     speaker may also examine connections in an OpenSent state if it
     knows the BGP Identifier of the peer by means outside of the
     protocol.  If among these connections there is a connection to a
     remote BGP speaker whose BGP Identifier equals the one in the
     OPEN message, then the local system performs the following
     collision resolution procedure: */

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer == new)
        continue;
      if (!sockunion_same (&peer->su, &new->su))
        continue;
      
      /* Unless allowed via configuration, a connection collision with an
         existing BGP connection that is in the Established state causes
         closing of the newly created connection. */
      if (peer->status == Established)
        {
          /* GR may do things slightly differently to classic RFC .  Punt to
           * open_receive, see below 
           */
          if (CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_MODE))
            continue;
          
          if (new->fd >= 0)
            {
              if (BGP_DEBUG (events, EVENTS))
                 zlog_debug ("%s:%u Existing Established peer, sending NOTIFY",
                             new->host, sockunion_get_port (&new->su));
              bgp_notify_send (new, BGP_NOTIFY_CEASE, 
                               BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
            }
          return -1;
        }
      
      /* Note: Quagga historically orders explicitly only on the processing
       * of the Opens, treating 'new' as the passive, inbound and connection
       * and 'peer' as the active outbound connection.
       */
       
      /* The local_id is always set, so we can match the given remote-ID
       * from the OPEN against both OpenConfirm and OpenSent peers.
       */
      if (peer->status == OpenConfirm || peer->status == OpenSent)
  {
    struct peer *out = peer;
    struct peer *in = new;
    int ret_close_out = 1, ret_close_in = -1;
    
    if (!CHECK_FLAG (new->sflags, PEER_STATUS_ACCEPT_PEER))
      {
        out = new;
        ret_close_out = -1;
        in = peer;
        ret_close_in = 1;
      }
          
    /* 1. The BGP Identifier of the local system is compared to
       the BGP Identifier of the remote system (as specified in
       the OPEN message). */

    if (ntohl (peer->local_id.s_addr) < ntohl (remote_id.s_addr))
      {
        /* 2. If the value of the local BGP Identifier is less
     than the remote one, the local system closes BGP
     connection that already exists (the one that is
     already in the OpenConfirm state), and accepts BGP
     connection initiated by the remote system. */

        if (out->fd >= 0)
          {
            if (BGP_DEBUG (events, EVENTS))
               zlog_debug ("%s Collision resolution, remote ID higher,"
                           " closing outbound", peer->host);
      bgp_notify_send (out, BGP_NOTIFY_CEASE, 
                       BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
                }
        return ret_close_out;
      }
    else
      {
        /* 3. Otherwise, the local system closes newly created
     BGP connection (the one associated with the newly
     received OPEN message), and continues to use the
     existing one (the one that is already in the
     OpenConfirm state). */

        if (in->fd >= 0)
          {
            if (BGP_DEBUG (events, EVENTS))
               zlog_debug ("%s Collision resolution, local ID higher,"
                           " closing inbound", peer->host);

                  bgp_notify_send (in, BGP_NOTIFY_CEASE, 
                 BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
                }
        return ret_close_in;
      }
  }
    }
  return 0;
}

static int
bgp_open_receive (struct peer *peer, bgp_size_t size)
{
  int ret;
  u_char version;
  u_char optlen;
  u_int16_t holdtime;
  u_int16_t send_holdtime;
  as_t remote_as;
  as_t as4 = 0;
  struct peer *realpeer;
  struct in_addr remote_id;
  int mp_capability;
  u_int8_t notify_data_remote_as[2];
  u_int8_t notify_data_remote_id[4];

  realpeer = NULL;
  
  /* Parse open packet. */
  version = stream_getc (peer->ibuf);
  memcpy (notify_data_remote_as, stream_pnt (peer->ibuf), 2);
  remote_as  = stream_getw (peer->ibuf);
  holdtime = stream_getw (peer->ibuf);
  memcpy (notify_data_remote_id, stream_pnt (peer->ibuf), 4);
  remote_id.s_addr = stream_get_ipv4 (peer->ibuf);

  /* Receive OPEN message log  */
  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s rcv OPEN, version %d, remote-as (in open) %u,"
                " holdtime %d, id %s, %sbound connection",
          peer->host, version, remote_as, holdtime,
          inet_ntoa (remote_id),
          CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER)
            ? "in" : "out");
  
  /* BEGIN to read the capability here, but dont do it yet */
  mp_capability = 0;
  optlen = stream_getc (peer->ibuf);
  
  if (optlen != 0)
    {
      /* We need the as4 capability value *right now* because
       * if it is there, we have not got the remote_as yet, and without
       * that we do not know which peer is connecting to us now.
       */ 
      as4 = peek_for_as4_capability (peer, optlen);
    }
  
  /* Just in case we have a silly peer who sends AS4 capability set to 0 */
  if (CHECK_FLAG (peer->cap, PEER_CAP_AS4_RCV) && !as4)
    {
      zlog_err ("%s bad OPEN, got AS4 capability, but AS4 set to 0",
                peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_OPEN_ERR,
                       BGP_NOTIFY_OPEN_BAD_PEER_AS);
      return -1;
    }
  
  if (remote_as == BGP_AS_TRANS)
    {
    /* Take the AS4 from the capability.  We must have received the
     * capability now!  Otherwise we have a asn16 peer who uses
     * BGP_AS_TRANS, for some unknown reason.
     */
      if (as4 == BGP_AS_TRANS)
        {
          zlog_err ("%s [AS4] NEW speaker using AS_TRANS for AS4, not allowed",
                    peer->host);
          bgp_notify_send (peer, BGP_NOTIFY_OPEN_ERR,
                 BGP_NOTIFY_OPEN_BAD_PEER_AS);
          return -1;
        }
      
      if (!as4 && BGP_DEBUG (as4, AS4))
        zlog_debug ("%s [AS4] OPEN remote_as is AS_TRANS, but no AS4."
                    " Odd, but proceeding.", peer->host);
      else if (as4 < BGP_AS_MAX && BGP_DEBUG (as4, AS4))
        zlog_debug ("%s [AS4] OPEN remote_as is AS_TRANS, but AS4 (%u) fits "
                    "in 2-bytes, very odd peer.", peer->host, as4);
      if (as4)
        remote_as = as4;
    } 
  else 
    {
      /* We may have a partner with AS4 who has an asno < BGP_AS_MAX */
      /* If we have got the capability, peer->as4cap must match remote_as */
      if (CHECK_FLAG (peer->cap, PEER_CAP_AS4_RCV)
          && as4 != remote_as)
        {
    /* raise error, log this, close session */
    zlog_err ("%s bad OPEN, got AS4 capability, but remote_as %u"
              " mismatch with 16bit 'myasn' %u in open",
              peer->host, as4, remote_as);
    bgp_notify_send (peer, BGP_NOTIFY_OPEN_ERR,
         BGP_NOTIFY_OPEN_BAD_PEER_AS);
    return -1;
  }
    }

  /* Lookup peer from Open packet. */
  if (CHECK_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER))
    {
      int as = 0;

      realpeer = peer_lookup_with_open (&peer->su, remote_as, &remote_id, &as);

      if (! realpeer)
  {
    /* Peer's source IP address is check in bgp_accept(), so this
       must be AS number mismatch or remote-id configuration
       mismatch. */
    if (as)
      {
        if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s bad OPEN, wrong router identifier %s",
          peer->host, inet_ntoa (remote_id));
        bgp_notify_send_with_data (peer, BGP_NOTIFY_OPEN_ERR, 
           BGP_NOTIFY_OPEN_BAD_BGP_IDENT,
           notify_data_remote_id, 4);
      }
    else
      {
        if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s bad OPEN, remote AS is %u, expected %u",
          peer->host, remote_as, peer->as);
        bgp_notify_send_with_data (peer, BGP_NOTIFY_OPEN_ERR,
           BGP_NOTIFY_OPEN_BAD_PEER_AS,
           notify_data_remote_as, 2);
      }
    return -1;
  }
    }

  /* When collision is detected and this peer is closed.  Retrun
     immidiately. */
  ret = bgp_collision_detect (peer, remote_id);
  if (ret < 0)
    return ret;

  /* Bit hacky */
  if (CHECK_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER))
    { 
      /* Connection FSM state is intertwined with our peer configuration
       * (the RFC encourages this a bit).  At _this_ point we have a
       * 'realpeer' which represents the configuration and any earlier FSM
       * (outbound, unless the remote side has opened two connections to
       * us), and a 'peer' which here represents an inbound connection that
       * has not yet been reconciled with a 'realpeer'.  
       * 
       * As 'peer' has just sent an OPEN that reconciliation must now
       * happen, as only the 'realpeer' can ever proceed to Established.
       *
       * bgp_collision_detect should have resolved any collisions with
       * realpeers that are in states OpenSent, OpenConfirm or Established,
       * and may have sent a notify on the 'realpeer' connection. 
       * bgp_accept will have rejected any connections where the 'realpeer'
       * is in Idle or >Established (though, that status may have changed
       * since).
       *
       * Need to finish off any reconciliation here, and ensure that
       * 'realpeer' is left holding any needed state from the appropriate
       * connection (fd, buffers, etc.), and any state from the other
       * connection is cleaned up.
       */

      /* Is realpeer in some globally-down state, that precludes any and all
       * connections (Idle, Clearing, Deleted, etc.)?
       */
      if (realpeer->status == Idle || realpeer->status > Established)
        {
          if (BGP_DEBUG (events, EVENTS))
            zlog_debug ("%s peer status is %s, closing the new connection",
                        realpeer->host, 
                        LOOKUP (bgp_status_msg, realpeer->status));
          return -1;
        }
      
      /* GR does things differently, and prefers any new connection attempts
       * over an Established one (why not just rely on KEEPALIVE and avoid
       * having to special case this?) */
      if (realpeer->status == Established
      && CHECK_FLAG (realpeer->sflags, PEER_STATUS_NSF_MODE))
  {
    realpeer->last_reset = PEER_DOWN_NSF_CLOSE_SESSION;
    SET_FLAG (realpeer->sflags, PEER_STATUS_NSF_WAIT);
  }
      else if (ret == 0) 
  {
    /* If we're here, RFC collision-detect did not reconcile the
     * connections, and the 'realpeer' is still available.  So
     * 'realpeer' must be 'Active' or 'Connect'.
     *
     * According to the RFC we should just let this connection (of the
     * accepted 'peer') continue on to Established if the other
     * onnection (the 'realpeer') is in a more larval state, and
     * reconcile them when OPEN is sent on the 'realpeer'.
     *
     * However, the accepted 'peer' must be reconciled with 'peer' at
     * this point, due to the implementation, if 'peer' is to be able
     * to proceed.  So it should be allowed to go to Established, as
     * long as the 'realpeer' was in Active or Connect state - which
     * /should/ be the case if we're here.
     *
     * So we should only need to sanity check that that is the case
     * here, and allow the code to get on with transferring the 'peer'
     * connection state over.
     */
          if (realpeer->status != Active && realpeer->status != Connect)
            {
              if (BGP_DEBUG (events, EVENTS))
                zlog_warn ("%s real peer status should be Active or Connect,"
                            " but is %s",
                            realpeer->host, 
                            LOOKUP (bgp_status_msg, realpeer->status));
        bgp_notify_send (realpeer, BGP_NOTIFY_CEASE,
             BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
            }
  }

      if (BGP_DEBUG (events, EVENTS))
  zlog_debug ("%s:%u [Event] Transfer accept BGP peer to real (state %s)",
       peer->host, sockunion_get_port (&peer->su), 
       LOOKUP (bgp_status_msg, realpeer->status));

      bgp_stop (realpeer);
      
      /* Transfer file descriptor. */
      realpeer->fd = peer->fd;
      peer->fd = -1;

      /* Transfer input buffer. */
      stream_free (realpeer->ibuf);
      realpeer->ibuf = peer->ibuf;
      realpeer->packet_size = peer->packet_size;
      peer->ibuf = NULL;
      
      /* Transfer output buffer, there may be an OPEN queued to send */
      stream_fifo_free (realpeer->obuf);
      realpeer->obuf = peer->obuf;
      peer->obuf = NULL;
      
      bool open_deferred
        = CHECK_FLAG (peer->sflags, PEER_STATUS_OPEN_DEFERRED);
      
      /* Transfer status. */
      realpeer->status = peer->status;
      bgp_stop (peer);
      
      /* peer pointer change */
      peer = realpeer;
      
      if (peer->fd < 0)
  {
    zlog_err ("bgp_open_receive peer's fd is negative value %d",
        peer->fd);
    return -1;
  }
      BGP_READ_ON (peer->t_read, bgp_read, peer->fd);
      if (stream_fifo_head (peer->obuf))
        BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
      
      /* hack: we may defer OPEN on accept peers, when there seems to be a
       * realpeer in progress, when an accept peer connection is opened. This
       * is to avoid interoperability issues, with test/conformance tools
       * particularly. See bgp_fsm.c::bgp_connect_success
       *
       * If OPEN was deferred there, then we must send it now.
       */
      if (open_deferred)
        bgp_open_send (peer);
    }

  /* remote router-id check. */
  if (remote_id.s_addr == 0
      || IPV4_CLASS_DE (ntohl (remote_id.s_addr))
      || ntohl (peer->local_id.s_addr) == ntohl (remote_id.s_addr))
    {
      if (BGP_DEBUG (normal, NORMAL))
  zlog_debug ("%s bad OPEN, wrong router identifier %s",
       peer->host, inet_ntoa (remote_id));
      bgp_notify_send_with_data (peer, 
         BGP_NOTIFY_OPEN_ERR, 
         BGP_NOTIFY_OPEN_BAD_BGP_IDENT,
         notify_data_remote_id, 4);
      return -1;
    }

  /* Set remote router-id */
  peer->remote_id = remote_id;

  /* Peer BGP version check. */
  if (version != BGP_VERSION_4)
    {
      u_int16_t maxver = htons(BGP_VERSION_4);
      /* XXX this reply may not be correct if version < 4  XXX */
      if (BGP_DEBUG (normal, NORMAL))
  zlog_debug ("%s bad protocol version, remote requested %d, local request %d",
       peer->host, version, BGP_VERSION_4);
      /* Data must be in network byte order here */
      bgp_notify_send_with_data (peer, 
         BGP_NOTIFY_OPEN_ERR, 
         BGP_NOTIFY_OPEN_UNSUP_VERSION,
         (u_int8_t *) &maxver, 2);
      return -1;
    }

  /* Check neighbor as number. */
  if (remote_as != peer->as)
    {
      if (BGP_DEBUG (normal, NORMAL))
  zlog_debug ("%s bad OPEN, remote AS is %u, expected %u",
       peer->host, remote_as, peer->as);
      bgp_notify_send_with_data (peer, 
         BGP_NOTIFY_OPEN_ERR, 
         BGP_NOTIFY_OPEN_BAD_PEER_AS,
         notify_data_remote_as, 2);
      return -1;
    }

  /* From the rfc: Upon receipt of an OPEN message, a BGP speaker MUST
     calculate the value of the Hold Timer by using the smaller of its
     configured Hold Time and the Hold Time received in the OPEN message.
     The Hold Time MUST be either zero or at least three seconds.  An
     implementation may reject connections on the basis of the Hold Time. */

  if (holdtime < 3 && holdtime != 0)
    {
      uint16_t netholdtime = htons (holdtime);
      bgp_notify_send_with_data (peer,
                     BGP_NOTIFY_OPEN_ERR,
                     BGP_NOTIFY_OPEN_UNACEP_HOLDTIME,
                                 (u_int8_t *) &netholdtime, 2);
      return -1;
    }
    
  /* From the rfc: A reasonable maximum time between KEEPALIVE messages
     would be one third of the Hold Time interval.  KEEPALIVE messages
     MUST NOT be sent more frequently than one per second.  An
     implementation MAY adjust the rate at which it sends KEEPALIVE
     messages as a function of the Hold Time interval. */

  if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
    send_holdtime = peer->holdtime;
  else
    send_holdtime = peer->bgp->default_holdtime;

  if (holdtime < send_holdtime)
    peer->v_holdtime = holdtime;
  else
    peer->v_holdtime = send_holdtime;

  peer->v_keepalive = peer->v_holdtime / 3;

  /* Open option part parse. */
  if (optlen != 0) 
    {
      if ((ret = bgp_open_option_parse (peer, optlen, &mp_capability)) < 0)
        {
          bgp_notify_send (peer,
                 BGP_NOTIFY_OPEN_ERR,
                 BGP_NOTIFY_OPEN_UNSPECIFIC);
    return ret;
        }
    }
  else
    {
      if (BGP_DEBUG (normal, NORMAL))
  zlog_debug ("%s rcvd OPEN w/ OPTION parameter len: 0",
       peer->host);
    }

  /* 
   * Assume that the peer supports the locally configured set of
   * AFI/SAFIs if the peer did not send us any Mulitiprotocol
   * capabilities, or if 'override-capability' is configured.
   */
  if (! mp_capability ||
      CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
    {
      peer->afc_nego[AFI_IP][SAFI_UNICAST] = peer->afc[AFI_IP][SAFI_UNICAST];
      peer->afc_nego[AFI_IP][SAFI_MULTICAST] = peer->afc[AFI_IP][SAFI_MULTICAST];
      peer->afc_nego[AFI_IP6][SAFI_UNICAST] = peer->afc[AFI_IP6][SAFI_UNICAST];
      peer->afc_nego[AFI_IP6][SAFI_MULTICAST] = peer->afc[AFI_IP6][SAFI_MULTICAST];
    }

  /* Get sockname. */
  bgp_getsockname (peer);
  peer->rtt = sockopt_tcp_rtt (peer->fd);

  BGP_EVENT_ADD (peer, Receive_OPEN_message);

  peer->packet_size = 0;
  if (peer->ibuf)
    stream_reset (peer->ibuf);

  return 0;
}

/* Frontend for NLRI parsing, to fan-out to AFI/SAFI specific parsers */
int
circa_nlri_parse (struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{

  switch (packet->safi)
    {
      case SAFI_UNICAST:
      case SAFI_MULTICAST:
        return circa_nlri_parse_ip (peer, attr, packet);
      case SAFI_MPLS_VPN:
      case SAFI_MPLS_LABELED_VPN:
        return bgp_nlri_parse_vpn (peer, attr, packet);
      case SAFI_ENCAP:
        return bgp_nlri_parse_encap (peer, attr, packet);
    }
  return -1;
}

/* Frontend for NLRI parsing, to fan-out to AFI/SAFI specific parsers */
int
bgp_nlri_parse (struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{
  switch (packet->safi)
    {
      case SAFI_UNICAST:
      case SAFI_MULTICAST:
        return bgp_nlri_parse_ip (peer, attr, packet);
      case SAFI_MPLS_VPN:
      case SAFI_MPLS_LABELED_VPN:
        return bgp_nlri_parse_vpn (peer, attr, packet);
      case SAFI_ENCAP:
        return bgp_nlri_parse_encap (peer, attr, packet);
    }
  return -1;
}


/* Make CIRCA_MSG_FIZZLE packet and send it to the peer. */

void
circa_fizzle_send (struct peer *peer,char  *passed_root_cause_event_id,char *passed_time_stamp)
{

  if(peer->status == Established){

zlog_debug ("Outgoing FIZZLE message for RCE_ID: %s  TIME_STAMP: %s from:%ld to: %ld",passed_root_cause_event_id,passed_time_stamp,peer->local_as,peer->as);

  long event_id_sequence_id;
  long event_id_router_id;
  long time_stamp_seq_number;
  long time_stamp_router_id;

  char *backup[EVENT_ID_LENGTH];
  char *backup_ts[TIME_STAMP_LENGTH];
  strncpy(backup,passed_root_cause_event_id,EVENT_ID_LENGTH);
  strncpy(backup_ts,passed_time_stamp,TIME_STAMP_LENGTH);
// zlog_debug ("1the event value %s  %s ",passed_root_cause_event_id,backup);
// zlog_debug ("1the time stamp value %s  %s ",passed_time_stamp,backup_ts);
  event_id_router_id = str_split(backup, ',',1);
  event_id_sequence_id = str_split(backup, ',',0);

  // zlog_debug ("2the event value %s  %s %ld",passed_root_cause_event_id,backup,event_id_sequence_id);
// zlog_debug ("2the time stamp value %s  %s ",passed_time_stamp,backup_ts);

// zlog_debug ("3the event value %s  %s %ld ",passed_root_cause_event_id,backup,event_id_router_id);
//zlog_debug ("3the time stamp value %s  %s ",passed_time_stamp,backup_ts);
  time_stamp_router_id = str_split(backup_ts, ',',1);
  time_stamp_seq_number = str_split(backup_ts, ',',0);


  afi_t afi;
  safi_t safi;
  struct stream *s;
  struct stream *snlri;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct stream *packet;
  struct bgp_node *rn = NULL;
  struct bgp_info *binfo = NULL;
  bgp_size_t total_attr_len = 0;
  unsigned long attrlen_pos = 0;
  int space_remaining = 0;
  int space_needed = 0;
  size_t mpattrlen_pos = 0;
  size_t mpattr_pos = 0;

  s = peer->work;
  stream_reset (s);
  snlri = peer->scratch;
  stream_reset (snlri);

      /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
     * one byte message type.
     */
  adv = BGP_ADV_FIFO_HEAD (&peer->sync[afi][safi]->update);
  //zlog_debug ("%s We are before the while (adv)", ".......................");
  s = stream_new (BGP_MAX_PACKET_SIZE);
  bgp_packet_set_marker (s, CIRCA_MSG_FIZZLE);
  /* write CIRCA sub type. We do not use sub type and directly use the main message type field for identifying all messages */
  stream_putl (s, CIRCA_MSG_FIZZLE);
  /* 2: Write root cause event ID */
  // zlog_debug ("We are writing event_id_sequence_id %ld in fizzle to %s",event_id_sequence_id,peer->host);
   stream_putl (s, event_id_sequence_id);
   /* write event id router id */
     // zlog_debug ("We are writing event_id_router_id %ld in fizzle to %s",event_id_router_id,peer->host);

   stream_putl (s, event_id_router_id);
   /* write time stamp seq number */
     // zlog_debug ("We are writing time_stamp_seq_number %ld in fizzle to %s",time_stamp_seq_number,peer->host);

   stream_putl (s, time_stamp_seq_number);
   /* write time stamp router id */
     // zlog_debug ("We are writing time_stamp_router_id %ld in fizzle to %s",time_stamp_router_id,peer->host);

  stream_putl (s, time_stamp_router_id);
  // zlog_debug ("We wrote time_stamp_router_id %ld in fizzle to %s",time_stamp_router_id,peer->host);

    /* 2: withdrawn routes length */
    stream_putw (s, 0);
    // zlog_debug ("We are at line 2595 ");
    /* 3: total attributes length - attrlen_pos stores the position */
    attrlen_pos = stream_get_endp (s);

    /* 4: if there is MP_REACH_NLRI attribute, that should be the first
     * attribute, according to draft-ietf-idr-error-handling. Save the
     * position.
     */
    mpattr_pos = stream_get_endp(s);

    packet = stream_dup (s);

    bgp_packet_set_size (packet);

    bgp_packet_add (peer, packet);
    // zlog_debug ("We are at line 4 ");
    BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
    // zlog_debug ("We are at line 5 ");
    stream_reset (s);

    stream_reset (snlri);

    zlog_debug ("We are at the returning packet point for sending FIZZLE for event id %s time stamp %s to %s",passed_root_cause_event_id,passed_time_stamp,peer->host);
    return packet;
  }
}


/* Parse CIRCA FIZZLE packet */
void
circa_fizzle_receive (struct peer *peer, bgp_size_t size)
{


  // zlog_debug ("we received a fizzle message from %s",peer->host);
  // printcause(&cause_head);

  char received_event_id[EVENT_ID_LENGTH];
  char received_time_stamp[TIME_STAMP_LENGTH];
  long event_id_sec_section;
  long event_id_router_id;
  long time_stamp_seq_number;
  long time_stamp_router_id;
  int ret, nlri_ret;
  u_char *end;
  struct stream *s;
  struct attr attr;
  struct attr_extra extra;
  bgp_size_t attribute_len;
  bgp_size_t update_len;
  bgp_size_t withdraw_len;
  int i;
  
  enum NLRI_TYPES {
    NLRI_UPDATE,
    NLRI_WITHDRAW,
    NLRI_MP_UPDATE,
    NLRI_MP_WITHDRAW,
    NLRI_TYPE_MAX,
  };
  struct bgp_nlri nlris[NLRI_TYPE_MAX];
  /* Status must be Established. */
  if (peer->status != Established) 
    {
      zlog_err ("%s [FSM] FIZZLE packet received under status %s",
    peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }
  /* Set initial values. */
  memset (&attr, 0, sizeof (struct attr));
  memset (&extra, 0, sizeof (struct attr_extra));
  memset (&nlris, 0, sizeof nlris);
  attr.extra = &extra;
  s = peer->ibuf;
  end = stream_pnt (s) + size;
  /* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
     Length is too large (i.e., if Unfeasible Routes Length + Total
     Attribute Length + 23 exceeds the message Length), then the Error
     Subcode is set to Malformed Attribute List.  */
  if (stream_pnt (s) + 2 > end)
    {
      //zlog_debug ("For FIZZLE message:[Error] Update packet error (packet length is short");
      zlog_err ("%s [Error] Update packet error"
    " (packet length is short for unfeasible length)",
    peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  int end_of_s = s->endp;
    /* get CIRCA subtype */
  long subtype = stream_getl (s);
  /* get root cause evnt id. */
  event_id_sec_section = stream_getl (s);
  event_id_router_id = stream_getl (s);
  sprintf(received_event_id, "%u", event_id_sec_section);
  strcat(received_event_id, ",");
  char * char_router_id_part_of_event_id[EVENT_ID_LENGTH];
  sprintf(char_router_id_part_of_event_id, "%u", event_id_router_id);
  strcat(received_event_id, char_router_id_part_of_event_id);
  /* get time stamp */
  time_stamp_seq_number = stream_getl (s);
  time_stamp_router_id = stream_getl (s);
  sprintf(received_time_stamp, "%u", time_stamp_seq_number);
  strcat(received_time_stamp, ",");
  char * char_time_stamp_part_of_time_stamp[EVENT_ID_LENGTH];

  sprintf(char_time_stamp_part_of_time_stamp, "%u", time_stamp_router_id);

  strcat(received_time_stamp, char_time_stamp_part_of_time_stamp);
  zlog_debug ("Receiving FIZZLE message for RCE_ID: %s  TIME_STAMP: %s from:%ld to: %ld",received_event_id,received_time_stamp,peer->as,peer->local_as);

  delete_from_sent(&sent_head,received_time_stamp,received_event_id);

  struct caused_time_stamps* our_time_stamp_ds = (struct caused_time_stamps*) malloc(sizeof(struct caused_time_stamps));
  // print_caused_time_stamp_ds(&caused_time_stamps_head);
  delete_time_stamp_from_generated_time_stamps(&caused_time_stamps_head,received_event_id,received_time_stamp);
  // print_caused_time_stamp_ds(&caused_time_stamps_head);

  if(check_if_sent_is_empty_second_version(&caused_time_stamps_head,received_event_id)&& check_if_we_are_the_owner_of_event(peer,event_id_router_id))
  {
        circa_dessimination_phase(received_event_id);
    }
  else
      {
        zlog_debug ("it seems the new sent is not empty! or we are not the owner!!");
        struct cause* cause_of_fizzle = (struct cause*) malloc(sizeof(struct cause));
        cause_of_fizzle = getcause(&(cause_head), received_time_stamp,received_event_id);
        if (cause_of_fizzle != NULL)
          {
            if (check_if_we_received_all_generated_time_stamps(&caused_time_stamps_head,cause_of_fizzle->received_timestamp))   
            {
            zlog_debug ("********** We are going to send back a fizzle to the cause of %s which is %s**********",received_time_stamp,cause_of_fizzle->received_timestamp);
            /* we will send a fizzle back message to the cause of received time stamp */
            circa_fizzle_send(cause_of_fizzle->received_from_peer,received_event_id,cause_of_fizzle->received_timestamp);
            }
          }
          else
          {
            /* this means we do not have any cause for the received time stamp !!!! */
            zlog_debug("Big Error!!!!! We did not get anything for received time stamp %s in case sent is empty after removing",received_time_stamp);
          }

        }
}
void 
circa_dessimination_phase (char * event_id)
{
  zlog_debug("****** we are at circa_dessimination_phase *****");
  if(get_converged_value(&converged_head, event_id)==0)
  {

  zlog_debug("***************************************************** CIRCA_MSG_DISSEMINATION  ******************");
  zlog_debug("***************************************************** %s root cause owner ****************",event_id);
  circa_fib_dispatching(event_id);
  set_converged_value_true(&converged_head, event_id);
  //circa_msg_fib_entry_send();

  struct neighbours_sent_to * neighbour_we_sent_them = (struct neighbours_sent_to *) malloc (sizeof(struct neighbours_sent_to));
  neighbour_we_sent_them = get_neighbours_sent_to(&(neighbours_sent_to_head),event_id);
  // zlog_debug (" lets print neighbors we have sent event to them");
  // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));
  // zlog_debug ("finished");
    if (neighbour_we_sent_them != NULL)
    {
        // zlog_debug (" this is our peers we have sent an update to");
        struct peer_list * my_temp = neighbour_we_sent_them -> peer_list ;
        //zlog_debug("********** going to print the peer list ********");
        while(my_temp != NULL)
        {   
            // zlog_debug("this is the host of the peer %s and lets send a convergence message to it", my_temp -> peer -> host);

            circa_dissemination_send (my_temp -> peer,event_id);
            
            my_temp = my_temp -> next;
         }
    }
    // else
    //     zlog_debug (" We have not sent this root cause event %s to any neighbor!!!",event_id);

}
// zlog_debug ("!!!!!!!!!!!!!!!!!this root cause event %s already has been convergend so we will not send dissemination phase message again!!!!!!!!!",event_id);


//     clear_time_stamp_for_event(event_id);
//     struct peer *peer;
// //    for(all peers in timestamp)
// //    {
// //        circa_dissemination_send(peer,event_id);
// //    }

  return 1;

}

/* Parse BGP CONVERGENCE packet */
void
circa_dissemination_receive (struct peer *peer, bgp_size_t size)
{
    // if(check_if_the_event_has_not_converged_already)
    // {
    //   set_converged(event_id);
    //   circa_dessimination_phase("E_id");
    // }



  long received_sub_type_code; 
  long received_event_seq_number;
  long received_event_router_id; 

  u_char *end;
  struct stream *s;
  
  /* Status must be Established. */
  if (peer->status != Established) 
    {
      zlog_err ("%s [FSM] CIRCA DISSEMINATION packet received under status %s",
    peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }

  s = peer->ibuf;
  char result7[50]; 
  end = stream_pnt (s) + size;
  if (  size == 4 )
    {
    zlog_debug ("2 we have received a circa message but the lenght is 4 which is error");
      return -1;
    }

  /* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
     Length is too large (i.e., if Unfeasible Routes Length + Total
     Attribute Length + 23 exceeds the message Length), then the Error
     Subcode is set to Malformed Attribute List.  */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_err ("%s [Error] CIRCA packet error"
    " (packet length is short for unfeasible length)",
    peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }
    int size_of_stream = s->size;
    int end_of_s = s->endp;
  /* get root cause evnt id. */
  received_sub_type_code = stream_getl (s);
  // zlog_debug ("this is received_sub_type_code %ld from %s",received_sub_type_code,peer->host);
  /* get sequence number . */
  received_event_seq_number = stream_getl (s);
  // zlog_debug ("this is received_event_seq_number %ld ",received_event_seq_number);
  /* get second sequence number which only being used in CBGP messages not in GRC messages . */
  received_event_router_id = stream_getl (s);
  // zlog_debug ("this is received_event_router_id %ld ",received_event_router_id);

  char * event_id[EVENT_ID_LENGTH];
  sprintf(event_id, "%u", received_event_seq_number);
  char * char_my_router_id[20];
  sprintf(char_my_router_id, "%u", received_event_router_id);
  strcat(event_id, ",");
  strcat(event_id, char_my_router_id);
  zlog_debug ("Receiving DISSEMINATION message for RCE_ID: %s from:%ld to:%ld",event_id,peer->as,peer->local_as);

  zlog_debug("***************************************************** STABLE STATE for RCE_ID: %s at router %ld ******************",event_id,peer->local_as);
  zlog_debug("***************************************************** %s  from %s ************************",event_id,peer->host);
  
  if(get_converged_value(&converged_head, event_id)==0)
  {
    circa_fib_dispatching(event_id);
    set_converged_value_true(&converged_head, event_id);
    struct neighbours_sent_to * neighbour_we_sent_them = (struct neighbours_sent_to *) malloc (sizeof(struct neighbours_sent_to));
    neighbour_we_sent_them = get_neighbours_sent_to(&(neighbours_sent_to_head),event_id);
    // zlog_debug (" lets print neighbors we have sent event to them");
    // print_neighbours_we_have_sent_event(&(neighbours_sent_to_head));
    // zlog_debug ("finished");
    if (neighbour_we_sent_them != NULL)
    {
        // zlog_debug (" this is our peers we have sent an update to");
        struct peer_list * my_temp = neighbour_we_sent_them -> peer_list ;
        zlog_debug("********** going to send fib entry to the peer list ********");
        while(my_temp != NULL)
        {   
            zlog_debug("this is the host of the peer %s and lets send a convergence message to it", my_temp -> peer -> host);
            circa_dissemination_send (my_temp -> peer,event_id);
            my_temp = my_temp -> next;
         }
    }
    else
    {
        zlog_debug (" We have not sent event %s to any neighbor!!! but we will send next hop to ground",event_id);
        if(avatar && peer->as==20 && peer->local_as==30)
        {
          zlog_debug ("We are sending 1 as next AS number in circa_msg_fib_entry_send function to be sent after receiving dessimination");
          circa_msg_fib_entry_send (avatar,event_id,NULL,NULL,NULL,1);
        }
      if(avatar && peer->as==10 && peer->local_as==30)
        {
          zlog_debug ("We are sending 2 as next AS number in circa_msg_fib_entry_send function to be sent after receiving dessimination");
          circa_msg_fib_entry_send (avatar,event_id,NULL,NULL,NULL,2);
        }
    }

  }
  else
    zlog_debug (" this event %s has been convergend before so we will not send down any fib for it!!!",event_id);
return ;
}

/* Make BGP_MSG_CONVERGENCE packet and send it to the peer. */

void
circa_dissemination_send (struct peer *peer,char  *passed_root_cause_event_id)
{


  if (peer->status == Established){

  zlog_debug ("Outgoing DISSEMINATION message for RCE_ID: %s from:%ld to:%ld",passed_root_cause_event_id,peer->local_as,peer->as);

  afi_t afi;
  safi_t safi;
  struct stream *s;
  struct stream *snlri;
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct stream *packet;
  struct bgp_node *rn = NULL;
  struct bgp_info *binfo = NULL;
  bgp_size_t total_attr_len = 0;
  unsigned long attrlen_pos = 0;
  int space_remaining = 0;
  int space_needed = 0;
  size_t mpattrlen_pos = 0;
  size_t mpattr_pos = 0;
  s = peer->work;
  stream_reset (s);
  snlri = peer->scratch;
  stream_reset (snlri);
      /* 1: Write the BGP message header - 16 bytes marker, 2 bytes length,
     * one byte message type.
     */
  s = stream_new (BGP_MAX_PACKET_SIZE);
  bgp_packet_set_marker (s, CIRCA_MSG_DISSEMINATION);
    /* 2: Write GRC subcode 2 for GRC message*/
   stream_putl (s, CIRCA_MSG_DISSEMINATION);
    /* 2: Write event id   */
   char backup_event_id[EVENT_ID_LENGTH];
  strncpy(backup_event_id,passed_root_cause_event_id,EVENT_ID_LENGTH);
    long router_id_value = str_split(backup_event_id, ',',1);
    long seq_number_sec = str_split(backup_event_id, ',',0);
   stream_putl (s, seq_number_sec);

    /* 2: Write seq  number2 as timestamp */

   stream_putl (s, router_id_value);

    /* 2: Write We have these fields reserved for concurrency control mechanism implementation */
   stream_putl (s, 1000);
   stream_putl (s, 1000);
   stream_putl (s, 1000);
   stream_putl (s, 1000);

    /* 2: withdrawn routes length */
    stream_putw (s, 0);
    /* 3: total attributes length - attrlen_pos stores the position */
    attrlen_pos = stream_get_endp (s);
    stream_putw (s, 0);
    /* 4: if there is MP_REACH_NLRI attribute, that should be the first
     * attribute, according to draft-ietf-idr-error-handling. Save the
     * position.
     */
    mpattr_pos = stream_get_endp(s);
    packet = stream_dup (s);
    bgp_packet_set_size (packet);
    bgp_packet_add (peer, packet);
    BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
    stream_reset (s);
    stream_reset (snlri);
    zlog_debug ("We are at the returning packet point for sending CIRCA CIRCA_MSG_DISSEMINATION to %s", peer->host);    
    return packet;

}
}
// pouryousef
/* Parse CIRCA received fib entry for a list of prefixes and update the fib entry for them in ground. */
int
circa_fib_entry_receive (struct peer *peer, int size)
{

  zlog_debug (" *********************.     We received a CIRCA FIB message from %s  ***********",peer->host);


  long seq_number_part_of_event_id;
  long router_id_part_of_event_id;
  long seq_number_part_of_time_stamp;
  long router_id_part_of_time_stamp;
  long CIRCA_sub_type;
  bool this_is_withdraw = false;
  received_packet_is_withdraw = false;


  int ret, nlri_ret;
  u_char *end;
  struct stream *s;
  struct attr attr;
  struct attr_extra extra;
  bgp_size_t attribute_len;
  bgp_size_t update_len;
  bgp_size_t withdraw_len;
  int i;
  
  enum NLRI_TYPES {
    NLRI_UPDATE,
    NLRI_WITHDRAW,
    NLRI_MP_UPDATE,
    NLRI_MP_WITHDRAW,
    NLRI_TYPE_MAX,
  };
  struct bgp_nlri nlris[NLRI_TYPE_MAX];

  /* Status must be Established. */
  if (peer->status != Established) 
    {
      zlog_err ("%s [FSM] FIB packet received under status %s",
    peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }

  /* Set initial values. */
  memset (&attr, 0, sizeof (struct attr));
  memset (&extra, 0, sizeof (struct attr_extra));
  memset (&nlris, 0, sizeof nlris);

  attr.extra = &extra;

  s = peer->ibuf;
  end = stream_pnt (s) + size;

  /* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
     Length is too large (i.e., if Unfeasible Routes Length + Total
     Attribute Length + 23 exceeds the message Length), then the Error
     Subcode is set to Malformed Attribute List.  */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_err ("%s [Error] FIB packet error"
    " (packet length is short for unfeasible length)",
    peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }
    /* get CIRCA related fields */
    CIRCA_sub_type = stream_getl (s);
    zlog_debug ("this is CIRCA_sub_type %ld from %s",CIRCA_sub_type,peer->host);


    /* get event id sequence number section */
    seq_number_part_of_event_id = stream_getl (s);
    zlog_debug ("this is seq_number_part_of_event_id %ld from %s",seq_number_part_of_event_id,peer->host);

    /* get event id router id section */
    router_id_part_of_event_id = stream_getl (s);
 zlog_debug ("this is router_id_part_of_event_id %ld from %s",router_id_part_of_event_id,peer->host);

    /* get time stamp sequence number section */
    seq_number_part_of_time_stamp = stream_getl (s);
    zlog_debug ("this is seq_number_part_of_time_stamp %ld from %s",seq_number_part_of_time_stamp,peer->host);

    /* get time stamp router id section */
    router_id_part_of_time_stamp = stream_getl (s);
 zlog_debug ("this is router_id_part_of_time_stamp %ld from %s",router_id_part_of_time_stamp,peer->host);

  /* Unfeasible Route Length. */
  withdraw_len = stream_getw (s);

  /* Unfeasible Route Length check. */
  if (stream_pnt (s) + withdraw_len > end)
    {
      zlog_err ("%s [Error] FIB packet error"
    " (packet unfeasible length overflow %d)",
    peer->host, withdraw_len);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Unfeasible Route packet format check. */
  if (withdraw_len > 0)
    {
      nlris[NLRI_WITHDRAW].afi = AFI_IP;
      nlris[NLRI_WITHDRAW].safi = SAFI_UNICAST;
      nlris[NLRI_WITHDRAW].nlri = stream_pnt (s);
      nlris[NLRI_WITHDRAW].length = withdraw_len;
      
      if (BGP_DEBUG (packet, PACKET_RECV))
  zlog_debug ("%s [FIB:RECV] Unfeasible NLRI received", peer->host);

      stream_forward_getp (s, withdraw_len);
    }
  
  /* Attribute total length check. */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_warn ("%s [Error] Packet Error"
     " (fib packet is short for attribute length)",
     peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Fetch attribute total length. */
  attribute_len = stream_getw (s);

  /* Attribute length check. */
  if (stream_pnt (s) + attribute_len > end)
    {
      zlog_warn ("%s [Error] Packet Error"
     " (fib packet attribute length overflow %d)",
     peer->host, attribute_len);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }
  
  /* Certain attribute parsing errors should not be considered bad enough
   * to reset the session for, most particularly any partial/optional
   * attributes that have 'tunneled' over speakers that don't understand
   * them. Instead we withdraw only the prefix concerned.
   * 
   * Complicates the flow a little though..
   */
  bgp_attr_parse_ret_t attr_parse_ret = BGP_ATTR_PARSE_PROCEED;
  /* This define morphs the update case into a withdraw when lower levels
   * have signalled an error condition where this is best.
   */
#define NLRI_ATTR_ARG (attr_parse_ret != BGP_ATTR_PARSE_WITHDRAW ? &attr : NULL)

  /* Parse attribute when it exists. */
  if (attribute_len)
    {
      zlog_debug ("*******... lets call bgp_attr_parse for received FIB entry message from %s and stream_pnt (s) is %ld ",peer->host,stream_pnt (s));
      attr_parse_ret = circa_fib_attr_parse (peer, &attr, attribute_len, 
          &nlris[NLRI_MP_UPDATE], &nlris[NLRI_MP_WITHDRAW]);
      if (attr_parse_ret == BGP_ATTR_PARSE_ERROR)
  {
    zlog_debug ("*******... we did have an error after calling bgp_attr_parse and stream_pnt (s); is  %ld but we will continue",stream_pnt (s));
    //bgp_attr_unintern_sub (&attr);
         // bgp_attr_flush (&attr);
    //return -1;
  }
    }
  zlog_debug ("*******... we did call bgp_attr_parse for received FIB entry message from %s",peer->host);

  /* Logging the attribute. */
  if (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
    {
      char attrstr[BUFSIZ];
      attrstr[0] = '\0';

      ret= bgp_dump_attr (peer, &attr, attrstr, BUFSIZ);
      int lvl = (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
                 ? LOG_ERR : LOG_DEBUG;
      
      if (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
        zlog (peer->log, LOG_ERR,
              "%s rcvd FIB with errors in attr(s)!! Withdrawing route.",
              peer->host);

      if (ret)
      {
          zlog_debug ("*******... we start parsing FIB message received from %ld",peer->as);
  zlog (peer->log, lvl, "%s rcvd FIB w/ attr: %s from %ld",
        peer->host, attrstr,peer->as);
      }
    }

    /* CIRCA: start with a empty list for prefixes */
  prefix_list_head = NULL;
  event_affected_prefix_list_head = NULL;
  /* Network Layer Reachability Information. */
  update_len = end - stream_pnt (s);

  if (update_len)
    {
      /* Set NLRI portion to structure. */
      nlris[NLRI_UPDATE].afi = AFI_IP;
      nlris[NLRI_UPDATE].safi = SAFI_UNICAST;
      nlris[NLRI_UPDATE].nlri = stream_pnt (s);
      nlris[NLRI_UPDATE].length = update_len;
      
      stream_forward_getp (s, update_len);
    }
  
  /* Parse any given NLRIs */
  for (i = NLRI_UPDATE; i < NLRI_TYPE_MAX; i++)
    {
      if (!nlris[i].nlri) continue;
      
      /* We use afi and safi as indices into tables and what not.  It would
       * be impossible, at this time, to support unknown afi/safis.  And
       * anyway, the peer needs to be configured to enable the afi/safi
       * explicitly which requires UI support.
       *
       * Ignore unknown afi/safi NLRIs.
       *
       * Note: this means nlri[x].afi/safi still can not be trusted for
       * indexing later in this function!
       *
       * Note2: This will also remap the wire code-point for VPN safi to the
       * internal safi_t point, as needs be.
       */
      if (!bgp_afi_safi_valid_indices (nlris[i].afi, &nlris[i].safi))
        {
          plog_info (peer->log,
                     "%s [Info] FIB with unsupported AFI/SAFI %u/%u",
                     peer->host, nlris[i].afi, nlris[i].safi);
          continue;
        }
      
      /* NLRI is processed only when the peer is configured specific
         Address Family and Subsequent Address Family. */
      if (!peer->afc[nlris[i].afi][nlris[i].safi])
        {
          plog_info (peer->log,
                     "%s [Info] FIB for non-enabled AFI/SAFI %u/%u",
                     peer->host, nlris[i].afi, nlris[i].safi);
          continue;
        }
      
      /* EoR handled later */
      if (nlris[i].length == 0)
        continue;
      
      switch (i)
        {
          case NLRI_UPDATE:
          case NLRI_MP_UPDATE:
            zlog_debug("wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww  start calling circa_nlri_parse for %s \n",peer->host);
            nlri_ret = circa_nlri_parse (peer, NLRI_ATTR_ARG, &nlris[i]);
            break;
          case NLRI_WITHDRAW:
          case NLRI_MP_WITHDRAW:
            zlog_debug("this is wrong!!! we supposed to start calling circa_nlri_parse for %s \n",peer->host);
            nlri_ret = bgp_nlri_parse (peer, NULL, &nlris[i]);
            this_is_withdraw= true;
            // zlog_debug("wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww %s start adding time stamp!!!! \n",peer->host);
          
          // zlog_debug("wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww %s finished!!!! \n",peer->host);
        }
    }
  
  
  

  /* If peering is stopped due to some reason, do not generate BGP
     event.  */
  if (peer->status != Established)
    return 0;

  return 0;
}

/* Parse BGP Update packet and make attribute object. */
int
circa_update_receive (struct peer *peer, int size)
{

  zlog_debug ("this is CIRCA CBGP message from %s ",peer->host);


  long seq_number_part_of_event_id;
  long router_id_part_of_event_id;
  long seq_number_part_of_time_stamp;
  long router_id_part_of_time_stamp;
  long CIRCA_sub_type;
  bool this_is_withdraw = false;
  received_packet_is_withdraw = false;

  int next_hop_AS_number = 2;
  int ret, nlri_ret;
  u_char *end;
  struct stream *s;
  struct attr attr;
  struct attr_extra extra;
  bgp_size_t attribute_len;
  bgp_size_t update_len;
  bgp_size_t withdraw_len;
  int i;
  
  enum NLRI_TYPES {
    NLRI_UPDATE,
    NLRI_WITHDRAW,
    NLRI_MP_UPDATE,
    NLRI_MP_WITHDRAW,
    NLRI_TYPE_MAX,
  };
  struct bgp_nlri nlris[NLRI_TYPE_MAX];

  /* Status must be Established. */
  if (peer->status != Established) 
    {
      zlog_err ("%s [FSM] Update packet received under status %s",
    peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }

  /* Set initial values. */
  memset (&attr, 0, sizeof (struct attr));
  memset (&extra, 0, sizeof (struct attr_extra));
  memset (&nlris, 0, sizeof nlris);

  attr.extra = &extra;

  s = peer->ibuf;
  end = stream_pnt (s) + size;

  /* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
     Length is too large (i.e., if Unfeasible Routes Length + Total
     Attribute Length + 23 exceeds the message Length), then the Error
     Subcode is set to Malformed Attribute List.  */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_err ("%s [Error] Update packet error"
    " (packet length is short for unfeasible length)",
    peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }
    /* get CIRCA related fields */
    CIRCA_sub_type = stream_getl (s);
    // zlog_debug ("this is CIRCA_sub_type %ld from %s",CIRCA_sub_type,peer->host);


    /* get event id sequence number section */
    seq_number_part_of_event_id = stream_getl (s);
    // zlog_debug ("this is seq_number_part_of_event_id %ld from %s",seq_number_part_of_event_id,peer->host);

    /* get event id router id section */
    router_id_part_of_event_id = stream_getl (s);
// zlog_debug ("this is router_id_part_of_event_id %ld from %s",router_id_part_of_event_id,peer->host);

    /* get time stamp sequence number section */
    seq_number_part_of_time_stamp = stream_getl (s);
    // zlog_debug ("this is seq_number_part_of_time_stamp %ld from %s",seq_number_part_of_time_stamp,peer->host);

    /* get time stamp router id section */
    router_id_part_of_time_stamp = stream_getl (s);
// zlog_debug ("this is router_id_part_of_time_stamp %ld from %s",router_id_part_of_time_stamp,peer->host);

  /* Unfeasible Route Length. */
  withdraw_len = stream_getw (s);

  /* Unfeasible Route Length check. */
  if (stream_pnt (s) + withdraw_len > end)
    {
      zlog_err ("%s [Error] Update packet error"
    " (packet unfeasible length overflow %d)",
    peer->host, withdraw_len);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Unfeasible Route packet format check. */
  if (withdraw_len > 0)
    {
      nlris[NLRI_WITHDRAW].afi = AFI_IP;
      nlris[NLRI_WITHDRAW].safi = SAFI_UNICAST;
      nlris[NLRI_WITHDRAW].nlri = stream_pnt (s);
      nlris[NLRI_WITHDRAW].length = withdraw_len;
      
      if (BGP_DEBUG (packet, PACKET_RECV))
  zlog_debug ("%s [Update:RECV] Unfeasible NLRI received", peer->host);

      stream_forward_getp (s, withdraw_len);
    }
  
  /* Attribute total length check. */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_warn ("%s [Error] Packet Error"
     " (update packet is short for attribute length)",
     peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Fetch attribute total length. */
  attribute_len = stream_getw (s);

  /* Attribute length check. */
  if (stream_pnt (s) + attribute_len > end)
    {
      zlog_warn ("%s [Error] Packet Error"
     " (update packet attribute length overflow %d)",
     peer->host, attribute_len);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }
  
  /* Certain attribute parsing errors should not be considered bad enough
   * to reset the session for, most particularly any partial/optional
   * attributes that have 'tunneled' over speakers that don't understand
   * them. Instead we withdraw only the prefix concerned.
   * 
   * Complicates the flow a little though..
   */
  bgp_attr_parse_ret_t attr_parse_ret = BGP_ATTR_PARSE_PROCEED;
  /* This define morphs the update case into a withdraw when lower levels
   * have signalled an error condition where this is best.
   */
#define NLRI_ATTR_ARG (attr_parse_ret != BGP_ATTR_PARSE_WITHDRAW ? &attr : NULL)

  /* Parse attribute when it exists. */
  if (attribute_len)
    {
    zlog_debug ("*******... lets call bgp_attr_parse for received CBGP entry message from %s and stream_pnt (s) is %ld ",peer->host,stream_pnt (s));
      attr_parse_ret = bgp_attr_parse (peer, &attr, attribute_len, 
          &nlris[NLRI_MP_UPDATE], &nlris[NLRI_MP_WITHDRAW]);
      if (attr_parse_ret == BGP_ATTR_PARSE_ERROR)
  {
    bgp_attr_unintern_sub (&attr);
          bgp_attr_flush (&attr);
    return -1;
  }
    }
  zlog_debug ("*******... did call bgp_attr_parse for received CBGP entry message from %s and stream_pnt (s) is %ld ",peer->host,stream_pnt (s));

  /* Logging the attribute. */
  if (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
    {
      char attrstr[BUFSIZ];
      attrstr[0] = '\0';

      ret= bgp_dump_attr (peer, &attr, attrstr, BUFSIZ);
      int lvl = (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
                 ? LOG_ERR : LOG_DEBUG;
      
      if (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
        zlog (peer->log, LOG_ERR,
              "%s rcvd UPDATE with errors in attr(s)!! Withdrawing route.",
              peer->host);

      if (ret)
      {
          zlog_debug ("*******... we start parsing update message received from %ld",peer->as);
  zlog (peer->log, lvl, "%s rcvd UPDATE w/ attr: %s from %ld",
        peer->host, attrstr,peer->as);
      }
    }

    /* CIRCA: start with a empty list for prefixes */
  prefix_list_head = NULL;
  event_affected_prefix_list_head = NULL;
  /* Network Layer Reachability Information. */
  update_len = end - stream_pnt (s);

  if (update_len)
    {
      /* Set NLRI portion to structure. */
      nlris[NLRI_UPDATE].afi = AFI_IP;
      nlris[NLRI_UPDATE].safi = SAFI_UNICAST;
      nlris[NLRI_UPDATE].nlri = stream_pnt (s);
      nlris[NLRI_UPDATE].length = update_len;
      
      stream_forward_getp (s, update_len);
    }
  
  /* Parse any given NLRIs */
  for (i = NLRI_UPDATE; i < NLRI_TYPE_MAX; i++)
    {
      if (!nlris[i].nlri) continue;
      
      /* We use afi and safi as indices into tables and what not.  It would
       * be impossible, at this time, to support unknown afi/safis.  And
       * anyway, the peer needs to be configured to enable the afi/safi
       * explicitly which requires UI support.
       *
       * Ignore unknown afi/safi NLRIs.
       *
       * Note: this means nlri[x].afi/safi still can not be trusted for
       * indexing later in this function!
       *
       * Note2: This will also remap the wire code-point for VPN safi to the
       * internal safi_t point, as needs be.
       */
      if (!bgp_afi_safi_valid_indices (nlris[i].afi, &nlris[i].safi))
        {
          plog_info (peer->log,
                     "%s [Info] UPDATE with unsupported AFI/SAFI %u/%u",
                     peer->host, nlris[i].afi, nlris[i].safi);
          continue;
        }
      
      /* NLRI is processed only when the peer is configured specific
         Address Family and Subsequent Address Family. */
      if (!peer->afc[nlris[i].afi][nlris[i].safi])
        {
          plog_info (peer->log,
                     "%s [Info] UPDATE for non-enabled AFI/SAFI %u/%u",
                     peer->host, nlris[i].afi, nlris[i].safi);
          continue;
        }
      
      /* EoR handled later */
      if (nlris[i].length == 0)
        continue;
      
      switch (i)
        {
          case NLRI_UPDATE:
          case NLRI_MP_UPDATE:
            nlri_ret = bgp_nlri_parse (peer, NLRI_ATTR_ARG, &nlris[i]);
            break;
          case NLRI_WITHDRAW:
          case NLRI_MP_WITHDRAW:
            nlri_ret = bgp_nlri_parse (peer, NULL, &nlris[i]);
            this_is_withdraw= true;
            // zlog_debug("wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww %s start adding time stamp!!!! \n",peer->host);
          
          // zlog_debug("wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww %s finished!!!! \n",peer->host);
        }
      


      if (nlri_ret < 0)
        {
          plog_err (peer->log, 
                    "%s [Error] Error parsing NLRI", peer->host);
          if (peer->status == Established)
            bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR,
                             i <= NLRI_WITHDRAW 
                               ? BGP_NOTIFY_UPDATE_INVAL_NETWORK
                               : BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
          bgp_attr_unintern_sub (&attr);
          return -1;
        }
    }
  
  /* EoR checks.
   *
   * Non-MP IPv4/Unicast EoR is a completely empty UPDATE
   * and MP EoR should have only an empty MP_UNREACH
   */
  if (!update_len && !withdraw_len
      && nlris[NLRI_MP_UPDATE].length == 0)
    {
      afi_t afi = 0;
      safi_t safi;
      
      /* Non-MP IPv4/Unicast is a completely empty UPDATE - already
       * checked update and withdraw NLRI lengths are 0.
       */ 
      if (!attribute_len)
        {
          afi = AFI_IP;
          safi = SAFI_UNICAST;
        }
      /* otherwise MP AFI/SAFI is an empty update, other than an empty
       * MP_UNREACH_NLRI attr (with an AFI/SAFI we recognise).
       */
      else if (attr.flag == BGP_ATTR_MP_UNREACH_NLRI
               && nlris[NLRI_MP_WITHDRAW].length == 0
               && bgp_afi_safi_valid_indices (nlris[NLRI_MP_WITHDRAW].afi,
                                              &nlris[NLRI_MP_WITHDRAW].safi))
        {
          afi = nlris[NLRI_MP_WITHDRAW].afi;
          safi = nlris[NLRI_MP_WITHDRAW].safi;
        }
      
      if (afi && peer->afc[afi][safi])
        {
    /* End-of-RIB received */
    SET_FLAG (peer->af_sflags[afi][safi],
        PEER_STATUS_EOR_RECEIVED);

    /* NSF delete stale route */
    if (peer->nsf[afi][safi])
      bgp_clear_stale_route (peer, afi, safi);

    if (BGP_DEBUG (normal, NORMAL))
      zlog (peer->log, LOG_DEBUG, "rcvd End-of-RIB for %s from %s",
      peer->host, afi_safi_print (afi, safi));
        }
    }
  
  

  /* Everything is done.  We unintern temporary structures which
     interned in bgp_attr_parse(). */
  bgp_attr_unintern_sub (&attr);
  bgp_attr_flush (&attr);

  /* If peering is stopped due to some reason, do not generate BGP
     event.  */
  if (peer->status != Established)
    return 0;
/* we will add the time stamp and prefix list of the received update to the time_stamp ds here 
   */
    char * in_event_id[EVENT_ID_LENGTH];
    char * in_time_stamp_id[TIME_STAMP_LENGTH];
    concat_long_values( seq_number_part_of_event_id,router_id_part_of_event_id ,&in_event_id,EVENT_ID_LENGTH);
    concat_long_values( seq_number_part_of_time_stamp, router_id_part_of_time_stamp,&in_time_stamp_id,TIME_STAMP_LENGTH);

    if (prefix_list_head != NULL)
    {
    
    // strncpy(in_time_stamp_id ,"time_stamp_id,987", TIME_STAMP_LENGTH);
    // strncpy(in_event_id ,"event_id,56789", EVENT_ID_LENGTH);
    char * aspath_str_value[PREFIX_LENGTH];
    if (this_is_withdraw)
    {
     strncpy(aspath_str_value,"withdraw",PREFIX_LENGTH);
    }
    else{
    // zlog_debug("we will copy aspath in aspath str %s",attr.aspath->str);
    strncpy(aspath_str_value,attr.aspath->str,PREFIX_LENGTH);
  }
    zlog_debug("\n ********************* we received an UPDATE message from %s with event id %s and time stamp %s and aspath_str_value %s ************ \n ",peer->host,in_event_id,in_time_stamp_id,aspath_str_value);
    // struct attr *riattr;
    //bgp_attr_dup (riattr,attr);
    zlog_debug("we are going to add new time stamp from bgp_packet file");
    add_new_time_stamp(&time_stamp_ds_head,in_event_id,in_time_stamp_id,peer->local_as,prefix_list_head,event_affected_prefix_list_head,peer,&attr,aspath_str_value);
    //shahrooz: required checking
    if(working_mode==1)
    {
      if(avatar)
      {
      //zlog_debug("***********************.        we are going to send down FIB ************** to %s",avatar->host);
        next_hop_AS_number = peer->as;
      if (next_hop_AS_number ==10)
        next_hop_AS_number = 1;
      if (next_hop_AS_number ==20)
        next_hop_AS_number = 2;  
      if (next_hop_AS_number ==30)
        next_hop_AS_number = 3; 
      //zlog_debug ("We are sending %d as next AS number in circa_msg_fib_entry_send function to be sent ",next_hop_AS_number);
      circa_msg_fib_entry_send (avatar,in_event_id,NULL,NULL,&attr,next_hop_AS_number);
      }
    }
    //zlog_debug("\n ********************* in saved attr we have  %s ************ \n ",attr.aspath->str);
    // struct attr * saved_attr = get_attr_of_event(&time_stamp_ds_head,in_event_id);
    // if (saved_attr==NULL)
    // zlog_debug("\n ********************* in got attr we have  %s ************ \n ",saved_attr->aspath->str);

    // zlog_debug("lets print received time stamp with their prefix list");
    // print_time_stamp(&time_stamp_ds_head);
    insert_in_converged(&converged_head, in_event_id);
  }
  /* in case we receive an update but we have not add any of its prefixes to the list, 
  that means we have rejected the prefixes because of import policy */
  else{
      zlog_debug("this update got fizzleded because of import policies! lets send back a fizzle");
      circa_fizzle_send (peer,in_event_id,in_time_stamp_id);
      // zlog_debug("we sent back a fizzle message for it");
  }
  /* Increment packet counter. */
  peer->update_in++;
  peer->update_time = bgp_clock ();

  /* Rearm holdtime timer */
  BGP_TIMER_OFF (peer->t_holdtime);
  bgp_timer_set (peer);

  return 0;
}

/* Parse BGP Update packet and make attribute object. */
static int
bgp_update_receive (struct peer *peer, bgp_size_t size)
{

  zlog_debug("We received a BGP update message");

  int ret, nlri_ret;
  u_char *end;
  struct stream *s;
  struct attr attr;
  struct attr_extra extra;
  bgp_size_t attribute_len;
  bgp_size_t update_len;
  bgp_size_t withdraw_len;
  int i;
  
  enum NLRI_TYPES {
    NLRI_UPDATE,
    NLRI_WITHDRAW,
    NLRI_MP_UPDATE,
    NLRI_MP_WITHDRAW,
    NLRI_TYPE_MAX,
  };
  struct bgp_nlri nlris[NLRI_TYPE_MAX];

  /* Status must be Established. */
  if (peer->status != Established) 
    {
      zlog_err ("%s [FSM] Update packet received under status %s",
    peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }

  /* Set initial values. */
  memset (&attr, 0, sizeof (struct attr));
  memset (&extra, 0, sizeof (struct attr_extra));
  memset (&nlris, 0, sizeof nlris);

  attr.extra = &extra;

  s = peer->ibuf;
  end = stream_pnt (s) + size;

  /* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
     Length is too large (i.e., if Unfeasible Routes Length + Total
     Attribute Length + 23 exceeds the message Length), then the Error
     Subcode is set to Malformed Attribute List.  */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_err ("%s [Error] Update packet error"
    " (packet length is short for unfeasible length)",
    peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Unfeasible Route Length. */
  withdraw_len = stream_getw (s);

  /* Unfeasible Route Length check. */
  if (stream_pnt (s) + withdraw_len > end)
    {
      zlog_err ("%s [Error] Update packet error"
    " (packet unfeasible length overflow %d)",
    peer->host, withdraw_len);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Unfeasible Route packet format check. */
  if (withdraw_len > 0)
    {
      nlris[NLRI_WITHDRAW].afi = AFI_IP;
      nlris[NLRI_WITHDRAW].safi = SAFI_UNICAST;
      nlris[NLRI_WITHDRAW].nlri = stream_pnt (s);
      nlris[NLRI_WITHDRAW].length = withdraw_len;
      
      if (BGP_DEBUG (packet, PACKET_RECV))
  zlog_debug ("%s [Update:RECV] Unfeasible NLRI received", peer->host);

      stream_forward_getp (s, withdraw_len);
    }
  
  /* Attribute total length check. */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_warn ("%s [Error] Packet Error"
     " (update packet is short for attribute length)",
     peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Fetch attribute total length. */
  attribute_len = stream_getw (s);

  /* Attribute length check. */
  if (stream_pnt (s) + attribute_len > end)
    {
      zlog_warn ("%s [Error] Packet Error"
     " (update packet attribute length overflow %d)",
     peer->host, attribute_len);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
           BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }
  
  /* Certain attribute parsing errors should not be considered bad enough
   * to reset the session for, most particularly any partial/optional
   * attributes that have 'tunneled' over speakers that don't understand
   * them. Instead we withdraw only the prefix concerned.
   * 
   * Complicates the flow a little though..
   */
  bgp_attr_parse_ret_t attr_parse_ret = BGP_ATTR_PARSE_PROCEED;
  /* This define morphs the update case into a withdraw when lower levels
   * have signalled an error condition where this is best.
   */
#define NLRI_ATTR_ARG (attr_parse_ret != BGP_ATTR_PARSE_WITHDRAW ? &attr : NULL)

  /* Parse attribute when it exists. */
  if (attribute_len)
    {
      attr_parse_ret = bgp_attr_parse (peer, &attr, attribute_len, 
          &nlris[NLRI_MP_UPDATE], &nlris[NLRI_MP_WITHDRAW]);
      if (attr_parse_ret == BGP_ATTR_PARSE_ERROR)
  {
    bgp_attr_unintern_sub (&attr);
          bgp_attr_flush (&attr);
    return -1;
  }
    }

  /* Logging the attribute. */
  if (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW
      || 1==1)
    {
      char attrstr[BUFSIZ];
      attrstr[0] = '\0';

      ret= bgp_dump_attr (peer, &attr, attrstr, BUFSIZ);
      int lvl = (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
                 ? LOG_ERR : LOG_DEBUG;
      
      if (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
        zlog (peer->log, LOG_ERR,
              "%s rcvd UPDATE with errors in attr(s)!! Withdrawing route.",
              peer->host);

      if (ret)
      {
          zlog_debug ("*******... we start parsing update message received from %ld",peer->as);
  zlog (peer->log, lvl, "%s rcvd UPDATE w/ attr: %s from %ld",
        peer->host, attrstr,peer->as);


      }
    }
  
  /* Network Layer Reachability Information. */
  update_len = end - stream_pnt (s);

  if (update_len)
    {
      /* Set NLRI portion to structure. */
      nlris[NLRI_UPDATE].afi = AFI_IP;
      nlris[NLRI_UPDATE].safi = SAFI_UNICAST;
      nlris[NLRI_UPDATE].nlri = stream_pnt (s);
      nlris[NLRI_UPDATE].length = update_len;
      
      stream_forward_getp (s, update_len);
    }
  
  /* Parse any given NLRIs */
  for (i = NLRI_UPDATE; i < NLRI_TYPE_MAX; i++)
    {
      if (!nlris[i].nlri) continue;
      
      /* We use afi and safi as indices into tables and what not.  It would
       * be impossible, at this time, to support unknown afi/safis.  And
       * anyway, the peer needs to be configured to enable the afi/safi
       * explicitly which requires UI support.
       *
       * Ignore unknown afi/safi NLRIs.
       *
       * Note: this means nlri[x].afi/safi still can not be trusted for
       * indexing later in this function!
       *
       * Note2: This will also remap the wire code-point for VPN safi to the
       * internal safi_t point, as needs be.
       */
      if (!bgp_afi_safi_valid_indices (nlris[i].afi, &nlris[i].safi))
        {
          plog_info (peer->log,
                     "%s [Info] UPDATE with unsupported AFI/SAFI %u/%u",
                     peer->host, nlris[i].afi, nlris[i].safi);
          continue;
        }
      
      /* NLRI is processed only when the peer is configured specific
         Address Family and Subsequent Address Family. */
      if (!peer->afc[nlris[i].afi][nlris[i].safi])
        {
          plog_info (peer->log,
                     "%s [Info] UPDATE for non-enabled AFI/SAFI %u/%u",
                     peer->host, nlris[i].afi, nlris[i].safi);
          continue;
        }
      
      /* EoR handled later */
      if (nlris[i].length == 0)
        continue;
      
      switch (i)
        {
          case NLRI_UPDATE:
          case NLRI_MP_UPDATE:
            nlri_ret = bgp_nlri_parse (peer, NLRI_ATTR_ARG, &nlris[i]);
            break;
          case NLRI_WITHDRAW:
          case NLRI_MP_WITHDRAW:
            nlri_ret = bgp_nlri_parse (peer, NULL, &nlris[i]);
        }
      
      if (nlri_ret < 0)
        {
          plog_err (peer->log, 
                    "%s [Error] Error parsing NLRI", peer->host);
          if (peer->status == Established)
            bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR,
                             i <= NLRI_WITHDRAW 
                               ? BGP_NOTIFY_UPDATE_INVAL_NETWORK
                               : BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
          bgp_attr_unintern_sub (&attr);
          return -1;
        }
    }
  
  /* EoR checks.
   *
   * Non-MP IPv4/Unicast EoR is a completely empty UPDATE
   * and MP EoR should have only an empty MP_UNREACH
   */
  if (!update_len && !withdraw_len
      && nlris[NLRI_MP_UPDATE].length == 0)
    {
      afi_t afi = 0;
      safi_t safi;
      
      /* Non-MP IPv4/Unicast is a completely empty UPDATE - already
       * checked update and withdraw NLRI lengths are 0.
       */ 
      if (!attribute_len)
        {
          afi = AFI_IP;
          safi = SAFI_UNICAST;
        }
      /* otherwise MP AFI/SAFI is an empty update, other than an empty
       * MP_UNREACH_NLRI attr (with an AFI/SAFI we recognise).
       */
      else if (attr.flag == BGP_ATTR_MP_UNREACH_NLRI
               && nlris[NLRI_MP_WITHDRAW].length == 0
               && bgp_afi_safi_valid_indices (nlris[NLRI_MP_WITHDRAW].afi,
                                              &nlris[NLRI_MP_WITHDRAW].safi))
        {
          afi = nlris[NLRI_MP_WITHDRAW].afi;
          safi = nlris[NLRI_MP_WITHDRAW].safi;
        }
      
      if (afi && peer->afc[afi][safi])
        {
    /* End-of-RIB received */
    SET_FLAG (peer->af_sflags[afi][safi],
        PEER_STATUS_EOR_RECEIVED);

    /* NSF delete stale route */
    if (peer->nsf[afi][safi])
      bgp_clear_stale_route (peer, afi, safi);

    if (BGP_DEBUG (normal, NORMAL))
      zlog (peer->log, LOG_DEBUG, "rcvd End-of-RIB for %s from %s",
      peer->host, afi_safi_print (afi, safi));
        }
    }
  
  /* Everything is done.  We unintern temporary structures which
     interned in bgp_attr_parse(). */
  bgp_attr_unintern_sub (&attr);
  bgp_attr_flush (&attr);

  /* If peering is stopped due to some reason, do not generate BGP
     event.  */
  if (peer->status != Established)
    return 0;

  /* Increment packet counter. */
  peer->update_in++;
  peer->update_time = bgp_clock ();

  /* Rearm holdtime timer */
  BGP_TIMER_OFF (peer->t_holdtime);
  bgp_timer_set (peer);

  return 0;
}

/* Notify message treatment function. */
static void
bgp_notify_receive (struct peer *peer, bgp_size_t size)
{
  struct bgp_notify bgp_notify;

  if (peer->notify.data)
    {
      XFREE (MTYPE_TMP, peer->notify.data);
      peer->notify.data = NULL;
      peer->notify.length = 0;
    }

  bgp_notify.code = stream_getc (peer->ibuf);
  bgp_notify.subcode = stream_getc (peer->ibuf);
  bgp_notify.length = size - 2;
  bgp_notify.data = NULL;

  /* Preserv notify code and sub code. */
  peer->notify.code = bgp_notify.code;
  peer->notify.subcode = bgp_notify.subcode;
  /* For further diagnostic record returned Data. */
  if (bgp_notify.length)
    {
      peer->notify.length = size - 2;
      peer->notify.data = XMALLOC (MTYPE_TMP, size - 2);
      memcpy (peer->notify.data, stream_pnt (peer->ibuf), size - 2);
    }

  /* For debug */
  {
    int i;
    int first = 0;
    char c[4];

    if (bgp_notify.length)
      {
  bgp_notify.data = XMALLOC (MTYPE_TMP, bgp_notify.length * 3);
  for (i = 0; i < bgp_notify.length; i++)
    if (first)
      {
        sprintf (c, " %02x", stream_getc (peer->ibuf));
        strcat (bgp_notify.data, c);
      }
    else
      {
        first = 1;
        sprintf (c, "%02x", stream_getc (peer->ibuf));
        strcpy (bgp_notify.data, c);
      }
      }

    bgp_notify_print(peer, &bgp_notify, "received");
    if (bgp_notify.data)
      {
        XFREE (MTYPE_TMP, bgp_notify.data);
        bgp_notify.data = NULL;
        bgp_notify.length = 0;
      }
  }

  /* peer count update */
  peer->notify_in++;

  if (peer->status == Established)
    peer->last_reset = PEER_DOWN_NOTIFY_RECEIVED;

  /* We have to check for Notify with Unsupported Optional Parameter.
     in that case we fallback to open without the capability option.
     But this done in bgp_stop. We just mark it here to avoid changing
     the fsm tables.  */
  if (bgp_notify.code == BGP_NOTIFY_OPEN_ERR &&
      bgp_notify.subcode == BGP_NOTIFY_OPEN_UNSUP_PARAM )
    UNSET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

  BGP_EVENT_ADD (peer, Receive_NOTIFICATION_message);
}

/* Keepalive treatment function -- get keepalive send keepalive */
static void
bgp_keepalive_receive (struct peer *peer, bgp_size_t size)
{
  if (BGP_DEBUG (keepalive, KEEPALIVE))  
    zlog_debug ("%s KEEPALIVE rcvd", peer->host); 
  
  BGP_EVENT_ADD (peer, Receive_KEEPALIVE_message);
}

/* Route refresh message is received. */
static void
bgp_route_refresh_receive (struct peer *peer, bgp_size_t size)
{
  afi_t afi;
  safi_t safi;
  struct stream *s;

  /* If peer does not have the capability, send notification. */
  if (! CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_ADV))
    {
      plog_err (peer->log, "%s [Error] BGP route refresh is not enabled",
    peer->host);
      bgp_notify_send (peer,
           BGP_NOTIFY_HEADER_ERR,
           BGP_NOTIFY_HEADER_BAD_MESTYPE);
      return;
    }

  /* Status must be Established. */
  if (peer->status != Established) 
    {
      plog_err (peer->log,
    "%s [Error] Route refresh packet received under status %s",
    peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return;
    }

  s = peer->ibuf;
  
  /* Parse packet. */
  afi = stream_getw (s);
  /* reserved byte */
  stream_getc (s);
  safi = stream_getc (s);

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s rcvd REFRESH_REQ for afi/safi: %d/%d",
         peer->host, afi, safi);

  /* Check AFI and SAFI. */
  if ((afi != AFI_IP && afi != AFI_IP6)
      || (safi != SAFI_UNICAST && safi != SAFI_MULTICAST
    && safi != SAFI_MPLS_LABELED_VPN))
    {
      if (BGP_DEBUG (normal, NORMAL))
  {
    zlog_debug ("%s REFRESH_REQ for unrecognized afi/safi: %d/%d - ignored",
         peer->host, afi, safi);
  }
      return;
    }

  /* Adjust safi code. */
  if (safi == SAFI_MPLS_LABELED_VPN)
    safi = SAFI_MPLS_VPN;

  if (size != BGP_MSG_ROUTE_REFRESH_MIN_SIZE - BGP_HEADER_SIZE)
    {
      u_char *end;
      u_char when_to_refresh;
      u_char orf_type;
      u_int16_t orf_len;

      if (size - (BGP_MSG_ROUTE_REFRESH_MIN_SIZE - BGP_HEADER_SIZE) < 5)
        {
          zlog_info ("%s ORF route refresh length error", peer->host);
          bgp_notify_send (peer, BGP_NOTIFY_CEASE, 0);
          return;
        }

      when_to_refresh = stream_getc (s);
      end = stream_pnt (s) + (size - 5);

      while ((stream_pnt (s) + 2) < end)
  {
    orf_type = stream_getc (s); 
    orf_len = stream_getw (s);
    
    /* orf_len in bounds? */
    if ((stream_pnt (s) + orf_len) > end)
      break; /* XXX: Notify instead?? */
    if (orf_type == ORF_TYPE_PREFIX
        || orf_type == ORF_TYPE_PREFIX_OLD)
      {
        uint8_t *p_pnt = stream_pnt (s);
        uint8_t *p_end = stream_pnt (s) + orf_len;
        struct orf_prefix orfp;
        u_char common = 0;
        u_int32_t seq;
        int psize;
        char name[BUFSIZ];
        int ret;

        if (BGP_DEBUG (normal, NORMAL))
    {
      zlog_debug ("%s rcvd Prefixlist ORF(%d) length %d",
           peer->host, orf_type, orf_len);
    }

              /* we're going to read at least 1 byte of common ORF header,
               * and 7 bytes of ORF Address-filter entry from the stream
               */
              if (orf_len < 7)
                break; 
                
        /* ORF prefix-list name */
        sprintf (name, "%s.%d.%d", peer->host, afi, safi);

        while (p_pnt < p_end)
    {
                  /* If the ORF entry is malformed, want to read as much of it
                   * as possible without going beyond the bounds of the entry,
                   * to maximise debug information.
                   */
      int ok;
      memset (&orfp, 0, sizeof (struct orf_prefix));
      common = *p_pnt++;
      /* after ++: p_pnt <= p_end */
      if (common & ORF_COMMON_PART_REMOVE_ALL)
        {
          if (BGP_DEBUG (normal, NORMAL))
      zlog_debug ("%s rcvd Remove-All pfxlist ORF request", peer->host);
          prefix_bgp_orf_remove_all (afi, name);
          break;
        }
      ok = ((size_t)(p_end - p_pnt) >= sizeof(u_int32_t)) ;
      if (ok)
        {
          memcpy (&seq, p_pnt, sizeof (u_int32_t));
                      p_pnt += sizeof (u_int32_t);
                      orfp.seq = ntohl (seq);
        }
      else
        p_pnt = p_end ;

      if ((ok = (p_pnt < p_end)))
        orfp.ge = *p_pnt++ ;      /* value checked in prefix_bgp_orf_set() */
      if ((ok = (p_pnt < p_end)))
        orfp.le = *p_pnt++ ;      /* value checked in prefix_bgp_orf_set() */
      if ((ok = (p_pnt < p_end)))
        orfp.p.prefixlen = *p_pnt++ ;
      orfp.p.family = afi2family (afi);   /* afi checked already  */

      psize = PSIZE (orfp.p.prefixlen);   /* 0 if not ok          */
      if (psize > prefix_blen(&orfp.p))   /* valid for family ?   */
        {
          ok = 0 ;
          psize = prefix_blen(&orfp.p) ;
        }
      if (psize > (p_end - p_pnt))        /* valid for packet ?   */
        {
          ok = 0 ;
          psize = p_end - p_pnt ;
        }

      if (psize > 0)
        memcpy (&orfp.p.u.prefix, p_pnt, psize);
      p_pnt += psize;

      if (BGP_DEBUG (normal, NORMAL))
        {
          char buf[INET6_BUFSIZ];

          zlog_debug ("%s rcvd %s %s seq %u %s/%d ge %d le %d%s",
               peer->host,
               (common & ORF_COMMON_PART_REMOVE ? "Remove" : "Add"),
               (common & ORF_COMMON_PART_DENY ? "deny" : "permit"),
               orfp.seq,
               inet_ntop (orfp.p.family, &orfp.p.u.prefix, buf, INET6_BUFSIZ),
               orfp.p.prefixlen, orfp.ge, orfp.le,
               ok ? "" : " MALFORMED");
        }

      if (ok)
        ret = prefix_bgp_orf_set (name, afi, &orfp,
           (common & ORF_COMMON_PART_DENY ? 0 : 1 ),
           (common & ORF_COMMON_PART_REMOVE ? 0 : 1));
                  
      if (!ok || (ok && ret != CMD_SUCCESS))
        {
          if (BGP_DEBUG (normal, NORMAL))
      zlog_debug ("%s Received misformatted prefixlist ORF."
                  " Remove All pfxlist", peer->host);
          prefix_bgp_orf_remove_all (afi, name);
          break;
        }
    }
        peer->orf_plist[afi][safi] =
       prefix_bgp_orf_lookup (afi, name);
      }
    stream_forward_getp (s, orf_len);
  }
      if (BGP_DEBUG (normal, NORMAL))
  zlog_debug ("%s rcvd Refresh %s ORF request", peer->host,
       when_to_refresh == REFRESH_DEFER ? "Defer" : "Immediate");
      if (when_to_refresh == REFRESH_DEFER)
  return;
    }

  /* First update is deferred until ORF or ROUTE-REFRESH is received */
  if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_ORF_WAIT_REFRESH))
    UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_ORF_WAIT_REFRESH);

  /* Perform route refreshment to the peer */
  bgp_announce_route (peer, afi, safi);
}

static int
bgp_capability_msg_parse (struct peer *peer, u_char *pnt, bgp_size_t length)
{
  u_char *end;
  struct capability_mp_data mpc;
  struct capability_header *hdr;
  u_char action;
  afi_t afi;
  safi_t safi;

  end = pnt + length;

  /* XXX: Streamify this */
  for (; pnt < end; pnt += hdr->length + 3)
    {      
      /* We need at least action, capability code and capability length. */
      if (pnt + 3 > end)
        {
          zlog_info ("%s Capability length error", peer->host);
          bgp_notify_send (peer, BGP_NOTIFY_CEASE, 0);
          return -1;
        }
      action = *pnt;
      hdr = (struct capability_header *)(pnt + 1);
      
      /* Action value check.  */
      if (action != CAPABILITY_ACTION_SET
    && action != CAPABILITY_ACTION_UNSET)
        {
          zlog_info ("%s Capability Action Value error %d",
         peer->host, action);
          bgp_notify_send (peer, BGP_NOTIFY_CEASE, 0);
          return -1;
        }

      if (BGP_DEBUG (normal, NORMAL))
  zlog_debug ("%s CAPABILITY has action: %d, code: %u, length %u",
       peer->host, action, hdr->code, hdr->length);

      /* Capability length check. */
      if ((pnt + hdr->length + 3) > end)
        {
          zlog_info ("%s Capability length error", peer->host);
          bgp_notify_send (peer, BGP_NOTIFY_CEASE, 0);
          return -1;
        }

      /* Fetch structure to the byte stream. */
      memcpy (&mpc, pnt + 3, sizeof (struct capability_mp_data));

      /* We know MP Capability Code. */
      if (hdr->code == CAPABILITY_CODE_MP)
        {
    afi = ntohs (mpc.afi);
    safi = mpc.safi;

          /* Ignore capability when override-capability is set. */
          if (CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
      continue;
          
          if (!bgp_afi_safi_valid_indices (afi, &safi))
            {
              if (BGP_DEBUG (normal, NORMAL))
                zlog_debug ("%s Dynamic Capability MP_EXT afi/safi invalid "
                            "(%u/%u)", peer->host, afi, safi);
              continue;
            }
          
    /* Address family check.  */
          if (BGP_DEBUG (normal, NORMAL))
            zlog_debug ("%s CAPABILITY has %s MP_EXT CAP for afi/safi: %u/%u",
                       peer->host,
                       action == CAPABILITY_ACTION_SET 
                       ? "Advertising" : "Removing",
                       ntohs(mpc.afi) , mpc.safi);
              
          if (action == CAPABILITY_ACTION_SET)
            {
              peer->afc_recv[afi][safi] = 1;
              if (peer->afc[afi][safi])
                {
                  peer->afc_nego[afi][safi] = 1;
                  bgp_announce_route (peer, afi, safi);
                }
            }
          else
            {
              peer->afc_recv[afi][safi] = 0;
              peer->afc_nego[afi][safi] = 0;

              if (peer_active_nego (peer))
                bgp_clear_route (peer, afi, safi, BGP_CLEAR_ROUTE_NORMAL);
              else
                BGP_EVENT_ADD (peer, BGP_Stop);
            }
        }
      else
        {
          zlog_warn ("%s unrecognized capability code: %d - ignored",
                     peer->host, hdr->code);
        }
    }
  return 0;
}

/* Dynamic Capability is received. 
 *
 * This is exported for unit-test purposes
 */
int
bgp_capability_receive (struct peer *peer, bgp_size_t size)
{
  u_char *pnt;

  /* Fetch pointer. */
  pnt = stream_pnt (peer->ibuf);

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s rcv CAPABILITY", peer->host);

  /* If peer does not have the capability, send notification. */
  if (! CHECK_FLAG (peer->cap, PEER_CAP_DYNAMIC_ADV))
    {
      plog_err (peer->log, "%s [Error] BGP dynamic capability is not enabled",
    peer->host);
      bgp_notify_send (peer,
           BGP_NOTIFY_HEADER_ERR,
           BGP_NOTIFY_HEADER_BAD_MESTYPE);
      return -1;
    }

  /* Status must be Established. */
  if (peer->status != Established)
    {
      plog_err (peer->log,
    "%s [Error] Dynamic capability packet received under status %s", peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }

  /* Parse packet. */
  return bgp_capability_msg_parse (peer, pnt, size);
}

/* BGP read utility function. */
static int
bgp_read_packet (struct peer *peer)
{
  int nbytes;
  int readsize;

  readsize = peer->packet_size - stream_get_endp (peer->ibuf);

  /* If size is zero then return. */
  if (! readsize)
    return 0;

  /* Read packet from fd. */
  nbytes = stream_read_try (peer->ibuf, peer->fd, readsize);

  /* If read byte is smaller than zero then error occurred. */
  if (nbytes < 0) 
    {
      /* Transient error should retry */
      if (nbytes == -2)
  return -1;

      plog_err (peer->log, "%s [Error] bgp_read_packet error: %s",
     peer->host, safe_strerror (errno));

      if (peer->status == Established) 
  {
    if (CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_MODE))
      {
        peer->last_reset = PEER_DOWN_NSF_CLOSE_SESSION;
        SET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT);
      }
    else
      peer->last_reset = PEER_DOWN_CLOSE_SESSION;
  }

      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return -1;
    }  

  /* When read byte is zero : clear bgp peer and return */
  if (nbytes == 0) 
    {
      if (BGP_DEBUG (events, EVENTS))
  plog_debug (peer->log, "%s [Event] BGP connection closed fd %d",
       peer->host, peer->fd);

      if (peer->status == Established) 
  {
    if (CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_MODE))
      {
        peer->last_reset = PEER_DOWN_NSF_CLOSE_SESSION;
        SET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT);
      }
    else
      peer->last_reset = PEER_DOWN_CLOSE_SESSION;
  }

      BGP_EVENT_ADD (peer, TCP_connection_closed);
      return -1;
    }

  /* We read partial packet. */
  if (stream_get_endp (peer->ibuf) != peer->packet_size)
    return -1;

  return 0;
}

/* Marker check. */
static int
bgp_marker_all_one (struct stream *s, int length)
{
  int i;

  for (i = 0; i < length; i++)
    if (s->data[i] != 0xff)
      return 0;

  return 1;
}

/* Recent thread time.
   On same clock base as bgp_clock (MONOTONIC)
   but can be time of last context switch to bgp_read thread. */
static time_t
bgp_recent_clock (void)
{
  return recent_relative_time().tv_sec;
}

/* Starting point of packet process function. */
int
bgp_read (struct thread *thread)
{
  
  

  int ret;
  u_char type = 0;
  u_char root_cause_id = 0;
  struct peer *peer;
  bgp_size_t size;
  char notify_data_length[2];

  /* Yes first of all get peer pointer. */
  peer = THREAD_ARG (thread);
  peer->t_read = NULL;
  //if (peer->packet_size == 0)// we get error because we have not callled BGP_READ_ON and 
  //there in nothing for peer->packet_size
      //zlog_debug ("%s We should get nothingor error as we have not called BGP_READ_ON yet ", "peer->packet_size");



  /* For non-blocking IO check. */
  if (peer->status == Connect)
    {
      bgp_connect_check (peer);
      goto done;
    }
  else
    {
      if (peer->fd < 0)
  {
    zlog_err ("bgp_read peer's fd is negative value %d", peer->fd);
    return -1;
  }

      BGP_READ_ON (peer->t_read, bgp_read, peer->fd);
    }
    //zlog_debug (" We got a message from %s", peer->host);

  /* Read packet header to determine type of the packet */
  if (peer->packet_size == 0)
    peer->packet_size = BGP_HEADER_SIZE;

  if (stream_get_endp (peer->ibuf) < BGP_HEADER_SIZE)
    {
    // zlog_debug (" I am in the line which stream_get_endp (peer->ibuf) < BGP_HEADER_SIZE");

      ret = bgp_read_packet (peer);

      /* Header read error or partial read packet. */
      if (ret < 0) 
      {     // zlog_debug (" Header read error or partial read packet and finished!!");


  goto done;
}

   //zlog_debug (" lets check the message type and size %s", peer->host);

      /* Get size and type. */
      stream_forward_getp (peer->ibuf, BGP_MARKER_SIZE);
     //zlog_debug (" lets check the message type and size after stream_forward_getp %s", peer->host);

      memcpy (notify_data_length, stream_pnt (peer->ibuf), 2);

     //zlog_debug (" lets check the message type and size after memcpy %s", peer->host);

      size = stream_getw (peer->ibuf);
      type = stream_getc (peer->ibuf);

      //zlog_debug (" we got type and size %s", peer->host);


  char result22[50]; 
  sprintf(result22, "%u", type);

 // zlog_debug ("%s the first Type", result22);




  char result32[50]; 
  sprintf(result32, "%u", size);


 // zlog_debug ("%s the first size is ", result32 );


      // if (type == BGP_MSG_FIZZLE)
      //   zlog_debug (" ...........=====this is a FIZZLE message from....======  %s", peer->host);
      
      // if (type == BGP_MSG_CONVERGENCE)
      //   zlog_debug (" ...........=====this is a CONVERGENCE message from....======  %s", peer->host);
      



      // if (type == BGP_MSG_FIZZLE)
      // {
      //   zlog_debug (" ...........=====this is a FIZZLE message from....======  %s", peer->host);
      //   bgp_fizzle_receive (peer, size);
        
      //   //   /* Clear input buffer. */
      //   // peer->packet_size = 0;
      //   // if (peer->ibuf)
      //   //   stream_reset (peer->ibuf);
      //   return 0;
      // }







      if (BGP_DEBUG (normal, NORMAL) && type != 2 && type != 0)
      {      


       //zlog_debug ("We got error due to type != 2 && type != 0 " );


  zlog_debug ("%s rcv message type %d, length (excl. header) %d",
       peer->host, type, size - BGP_HEADER_SIZE);
}

      /* Marker check */
      if (((type == BGP_MSG_OPEN) || (type == BGP_MSG_KEEPALIVE))
    && ! bgp_marker_all_one (peer->ibuf, BGP_MARKER_SIZE))
  {

   //zlog_debug ("We got error here " );



    bgp_notify_send (peer,
         BGP_NOTIFY_HEADER_ERR, 
         BGP_NOTIFY_HEADER_NOT_SYNC);
    goto done;
  }



      /* BGP type check. */
      if (type != BGP_MSG_OPEN && type != BGP_MSG_UPDATE 
    && type != BGP_MSG_NOTIFY && type != BGP_MSG_KEEPALIVE 
    && type != BGP_MSG_ROUTE_REFRESH_NEW
    && type != BGP_MSG_ROUTE_REFRESH_OLD
    && type != BGP_MSG_CAPABILITY 
    && type != CIRCA_MSG_FIZZLE
    && type != CIRCA_MSG_UPDATE
    && type != CIRCA_MSG_DISSEMINATION
    && type != CIRCA_MSG_GRC
    && type != CIRCA_MSG_FIB_ENTRY)
  {
    if (BGP_DEBUG (normal, NORMAL))
      plog_debug (peer->log,
          "%s unknown message type 0x%02x",
          peer->host, type);
    bgp_notify_send_with_data (peer,
             BGP_NOTIFY_HEADER_ERR,
             BGP_NOTIFY_HEADER_BAD_MESTYPE,
             &type, 1);
    goto done;
  }

  //zlog_debug (" lets check the Mimimum packet length  %s", peer->host);



      /* Mimimum packet length check. */
      if ((size < BGP_HEADER_SIZE)
    || (size > BGP_MAX_PACKET_SIZE)
    || (type == BGP_MSG_OPEN && size < BGP_MSG_OPEN_MIN_SIZE)
    || (type == BGP_MSG_UPDATE && size < BGP_MSG_UPDATE_MIN_SIZE)
    || (type == BGP_MSG_NOTIFY && size < BGP_MSG_NOTIFY_MIN_SIZE)
    || (type == BGP_MSG_KEEPALIVE && size != BGP_MSG_KEEPALIVE_MIN_SIZE)
    || (type == BGP_MSG_ROUTE_REFRESH_NEW && size < BGP_MSG_ROUTE_REFRESH_MIN_SIZE)
    || (type == BGP_MSG_ROUTE_REFRESH_OLD && size < BGP_MSG_ROUTE_REFRESH_MIN_SIZE)
    || (type == BGP_MSG_CAPABILITY && size < BGP_MSG_CAPABILITY_MIN_SIZE)
    || (type == CIRCA_MSG_UPDATE && size < CIRCA_MSG_MIN_SIZE)
    )
  {
    if (BGP_DEBUG (normal, NORMAL))
      plog_debug (peer->log,
          "%s bad message length - %d for %s",
          peer->host, size, 
          type == 128 ? "ROUTE-REFRESH" :
          bgp_type_str[(int) type]);
   zlog_debug (" we are going to call bgp_notify_send_with_data");
    bgp_notify_send_with_data (peer,
             BGP_NOTIFY_HEADER_ERR,
               BGP_NOTIFY_HEADER_BAD_MESLEN,
             (u_char *) notify_data_length, 2);
    goto done;
  }

      /* Adjust size to message length. */
      peer->packet_size = size;
    }


   //zlog_debug (" lets bgp_read_packet  %s", peer->host);

  ret = bgp_read_packet (peer);
  if (ret < 0) 
    goto done;

  /* Get size and type again. */
  size = stream_getw_from (peer->ibuf, BGP_MARKER_SIZE);
  type = stream_getc_from (peer->ibuf, BGP_MARKER_SIZE + 2);


  char result2[50]; 
  sprintf(result2, "%u", type);

 //zlog_debug ("%s this is the type of the  received packet", result2);




  char result[50]; 
  sprintf(result, "%u", size);


 //zlog_debug ("%s this is the size int  of received packet ", result );


  /* BGP packet dump function. */
  bgp_dump_packet (peer, type, peer->ibuf);
  
  size = (peer->packet_size - BGP_HEADER_SIZE);

  /* Read rest of the packet and call each sort of packet routine */

    //zlog_debug ("we are going to check the type in switch " );


  switch (type) 
    {
    case BGP_MSG_OPEN:
      peer->open_in++;
      bgp_open_receive (peer, size); /* XXX return value ignored! */
      break;
    case BGP_MSG_UPDATE:
      peer->readtime = bgp_recent_clock ();
      zlog_debug ("we received an update message from %ld",peer->as);
      bgp_update_receive (peer, size);
      break;
    case BGP_MSG_NOTIFY:
      bgp_notify_receive (peer, size);
      break;
    case BGP_MSG_KEEPALIVE:
      peer->readtime = bgp_recent_clock ();
      bgp_keepalive_receive (peer, size);
      break;
    case BGP_MSG_ROUTE_REFRESH_NEW:
    case BGP_MSG_ROUTE_REFRESH_OLD:
      peer->refresh_in++;
      bgp_route_refresh_receive (peer, size);
      break;
    case BGP_MSG_CAPABILITY:
      peer->dynamic_cap_in++;
      bgp_capability_receive (peer, size);
      break;
    case CIRCA_MSG_GRC:
      // zlog_debug ("%s The type of received packet is CIRCA_MSG_GRC, let's pars it from %s", "**************........",peer->host);
      CIRCA_GRC_messages_handler(peer,size);
      break;
    case CIRCA_MSG_UPDATE:
      // zlog_debug ("%s The type of received packet is CIRCA_MSG_UPDATE, let's pars it from %s", "**************........",peer->host);
      peer->readtime = bgp_recent_clock ();
      zlog_debug ("we received an update message from %ld",peer->as);
      circa_update_receive(peer,size);
      break;
    case CIRCA_MSG_FIZZLE:
      // zlog_debug ("%s The type of received packet is CIRCA_MSG_FIZZLE, let's pars it from %s", "**************........",peer->host);
      circa_fizzle_receive(peer,size);
      break;
    case CIRCA_MSG_DISSEMINATION:
      // zlog_debug ("%s The type of received packet is CIRCA_MSG_DISSEMINATION, let's pars it from %s", "***************..........",peer->host);
      circa_dissemination_receive(peer,size);
      break;
    case CIRCA_MSG_FIB_ENTRY:
      zlog_debug ("The type of received packet is CIRCA_MSG_FIB_ENTRY, let's pars it from %s", "***************........",peer->host);
      circa_fib_entry_receive(peer,size);
      //circa_fib_entry_list_of_prefixes_receive(peer,size);
      break;

    }

  /* Clear input buffer. */
  peer->packet_size = 0;
  if (peer->ibuf)
    stream_reset (peer->ibuf);

 done:
  if (CHECK_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER))
    {
      if (BGP_DEBUG (events, EVENTS))
  zlog_debug ("%s [Event] Accepting BGP peer delete", peer->host);
      peer_delete (peer);
    }
  return 0;
}