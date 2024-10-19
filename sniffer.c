#include <pcap.h>
#include <stdio.h>
#include <winsock2.h>   // For IP address conversion and network functions
#include <time.h>       // For capturing based on time

#pragma comment(lib, "ws2_32.lib")  // Link with Winsock library

// Global variables for capturing options
int capture_filter = 0; // 0 = all traffic, 1 = HTTP only, 2 = TCP only
FILE *output_file;

// Callback function invoked by pcap_loop() for every captured packet
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    printf("Packet captured! Length: %d\n", header->len);

    // Print first 14 bytes (Ethernet header)
    printf("Ethernet Header: ");
    for (int i = 0; i < 14; i++) {
        fprintf(output_file, "%02x ", pkt_data[i]);
        printf("%02x ", pkt_data[i]);
    }
    printf("\n");

    // Check if it's an IP packet (Ethernet type field is 0x0800 for IP)
    if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00) {
        printf("IP packet detected.\n");

        // Extract and print source and destination IP addresses
        struct in_addr ip_src, ip_dst;
        ip_src.S_un.S_addr = *(u_long *)(pkt_data + 26);  // Source IP (starting at byte 26)
        ip_dst.S_un.S_addr = *(u_long *)(pkt_data + 30);  // Destination IP (starting at byte 30)

        printf("Source IP: %s\n", inet_ntoa(ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_dst));

        // Write to output file
        fprintf(output_file, "\nSource IP: %s\n", inet_ntoa(ip_src));
        fprintf(output_file, "Destination IP: %s\n", inet_ntoa(ip_dst));
    }
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;        // Compiled filter program
    char filter_exp[100] = "";    // Filter expression

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return -1;
    }

    // Find all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return -1;
    }

    // List all available devices
    int i = 0;
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("No interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    // Prompt user to select an interface
    int selected_interface = 0;
    printf("Select a network interface to capture from (enter the number): ");
    scanf("%d", &selected_interface);

    // Find the corresponding interface
    i = 0;
    for (device = alldevs; device != NULL; device = device->next) {
        if (++i == selected_interface) {
            break; // We've found the selected interface
        }
    }

    if (device == NULL) {
        printf("Invalid selection.\n");
        return -1;
    }

    // Ask user to enter the capture time (in milliseconds)
    int capture_time_ms;
    printf("Enter the capture time in milliseconds: ");
    scanf("%d", &capture_time_ms);

    // Ask user to select filter option
    printf("Select capture filter:\n");
    printf("1. All traffic\n");
    printf("2. HTTP only (port 80)\n");
    printf("3. TCP only\n");
    printf("Enter your choice: ");
    scanf("%d", &capture_filter);

    // Set the appropriate filter expression
    switch (capture_filter) {
        case 2: // HTTP only
            strcpy(filter_exp, "tcp port 80");
            break;
        case 3: // TCP only
            strcpy(filter_exp, "tcp");
            break;
        default:
            strcpy(filter_exp, ""); // Capture all traffic
            break;
    }

    // Open the selected device for packet capture
    handle = pcap_open_live(device->name, 65536, 0, 1000, errbuf);  // Promiscuous mode disabled (3rd argument set to 0)
    if (handle == NULL) {
        printf("Unable to open the device: %s\n", errbuf);
        return -1;
    }

    // Compile the filter expression and apply it
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        return -1;
    }

    // Open file to save capture
    output_file = fopen("capture_output.txt", "w");
    if (output_file == NULL) {
        printf("Error opening file for writing.\n");
        return -1;
    }

    printf("Capturing on device: %s\n", device->name);

    // Capture packets for the specified duration
    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) * 1000 < capture_time_ms) {
        pcap_dispatch(handle, 1, packet_handler, NULL);  // Capture one packet at a time
    }

    // Close the capture handle and free devices
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    fclose(output_file);

    printf("Capture completed and saved to capture_output.txt.\n");

    // Cleanup Winsock
    WSACleanup();

    return 0;
}
