/*
 * Copyright (c) 2021 Linumiz
 */

#include <zephyr.h>
#include <device.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <drivers/uart.h>


#define FINGERPRINT_STARTCODE           0xEF01

#define FINGERPRINT_OK                  0x00

#define FINGERPRINT_VERIFYPASSWORD      0x13
#define FPM_CHECKSENSOR                 0x36
#define FPM_FIRMWARE_CHECK              0x3A
#define FPM_LED_CONFIG                  0x35

#define LED_CONTROL_CODE                0x02 // Control code | 0x01 breathing light | 0x02 flashing light |
                                             // 0x03 light always on | 0x04 light always off | 0x05 light gradually on |
                                             // 0x06 light gradually off
#define LED_SPEED                       0x60 // Speed 0x00-0xff
#define LED_COLOR_IDX                   0x02 // Color index | 0x01 red | 0x02 blue | 0x03 purple
#define LED_CYCLES                      0x02 //  Number of cycles | 0-infinite, 1-255

#define FPM_DEFAULT_TIMEOUT             1000

#define FPM_COMMANDPACKET               0x01
#define FINGERPRINT_ACKPACKET           0x07

#define FINGERPRINT_TIMEOUT             0xFF
#define FINGERPRINT_BADPACKET           0xFE

#define UART_DEVICE_NAME DT_LABEL(DT_NODELABEL(uart1))

int verify_passwd(const struct device *uart_dev)
{
        static uint8_t get_packet[12];

        uint16_t sum = FPM_COMMANDPACKET + 0x00 + 0x07 + FINGERPRINT_VERIFYPASSWORD + 0x00 + 0x00 + 0x00 + 0x00;

        uint8_t pkg_data[] = {
          FINGERPRINT_STARTCODE >> 8,
          FINGERPRINT_STARTCODE & 0xFF,
          0xFF,0xFF,0xFF,0xFF,
          FPM_COMMANDPACKET,
          0x00,0x07,
          FINGERPRINT_VERIFYPASSWORD,
          0x00,0x00,0x00,0x00,
          sum >> 8,sum & 0xFF
        };

        for(uint8_t i = 0;i<sizeof(pkg_data);i++) {
                uart_poll_out(uart_dev, pkg_data[i]);
        }

        uint64_t end = sys_clock_timeout_end_calc(K_MSEC(FPM_DEFAULT_TIMEOUT));
        int i = 0;

        while (1) {
                uint8_t c;
                int64_t remaining = end - sys_clock_tick_get();

        	if (remaining <= 0) {
        		return FINGERPRINT_TIMEOUT;
        	}

                if (uart_poll_in(uart_dev, &c) == 0) {
                        get_packet[i++] = c;
                        if (i == 12) {
                                break;
                        }
                }
        }

        if (get_packet[6] != FINGERPRINT_ACKPACKET) {
              printk("ACK packet error 0x%X\n",get_packet[6]);
              return FINGERPRINT_BADPACKET;
        }

        if (get_packet[9]  != FINGERPRINT_OK) {
                printk("FPS Device Password not verified\n");
        }

        return 0;

}

int led_blue_ctrl(const struct device *uart_dev)
{
        uint8_t get_packet[12];
        uint16_t new_sum = FPM_COMMANDPACKET + 0x00 + 0x07 + FPM_LED_CONFIG + LED_CONTROL_CODE +
                        LED_SPEED + LED_COLOR_IDX + LED_CYCLES;

        uint8_t new_pkg_data[16] = {
          FINGERPRINT_STARTCODE >> 8,
          FINGERPRINT_STARTCODE & 0xFF,
          0xFF,0xFF,0xFF,0xFF,
          FPM_COMMANDPACKET,
          0x00,0x07,
          FPM_LED_CONFIG, LED_CONTROL_CODE,
          LED_SPEED, LED_COLOR_IDX, LED_CYCLES,
          new_sum >> 8,new_sum & 0xFF
        };

        for(uint8_t i = 0; i < 16 ;i++) {
                uart_poll_out(uart_dev, new_pkg_data[i]);
        }

        uint64_t end = sys_clock_timeout_end_calc(K_MSEC(FPM_DEFAULT_TIMEOUT));
        int i = 0;

        while (1) {
                uint8_t c;
                int64_t remaining = end - sys_clock_tick_get();

        	if (remaining <= 0) {
        		return -EIO;
        	}

                if (uart_poll_in(uart_dev, &c) == 0) {
                        get_packet[i++] = c;
                        if (i == 12) {
                                break;
                        }
                }
        }

        if (get_packet[6] != FINGERPRINT_ACKPACKET) {
              printk("ACK packet error 0x%X\n",get_packet[6]);
              return FINGERPRINT_BADPACKET;
        }

        if (get_packet[9] != FINGERPRINT_OK) {
                printk("pakcet not received\n");
        }

        return 0;
}

uint8_t check_firmware(const struct device *uart_dev)
{
        uint8_t get_packet[44];
        uint16_t new_sum = FPM_COMMANDPACKET + 0x00 + 0x03 + FPM_FIRMWARE_CHECK;

        uint8_t new_pkg_data[] = {
          FINGERPRINT_STARTCODE >> 8,
          FINGERPRINT_STARTCODE & 0xFF,
          0xFF,0xFF,0xFF,0xFF,
          FPM_COMMANDPACKET,
          0x00,0x03,
          FPM_FIRMWARE_CHECK,
          new_sum >> 8,new_sum & 0xFF
        };

        for(uint8_t i = 0;i<sizeof(new_pkg_data);i++) {
                uart_poll_out(uart_dev, new_pkg_data[i]);
        }

        uint64_t end = sys_clock_timeout_end_calc(K_MSEC(FPM_DEFAULT_TIMEOUT));
        int i = 0;

        while (1) {
                uint8_t c;
                int64_t remaining = end - sys_clock_tick_get();

        	if (remaining <= 0) {
        		return -EIO;
        	}

                if (uart_poll_in(uart_dev, &c) == 0) {
                        get_packet[i++] = c;
                        if (i == 44) {
                                break;
                        }
                }
        }

        if (get_packet[6] != FINGERPRINT_ACKPACKET) {
              printk("ACK packet error 0x%X\n",get_packet[6]);
              return FINGERPRINT_BADPACKET;
        }

        if (get_packet[9] != FINGERPRINT_OK) {
                printk("pakcet not received\n");
        }

        printk("firmware version: ");
        for(uint8_t i = 10; i < sizeof(get_packet);i++)
        printk("%d",get_packet[i]);
        printk("\n");

        return 0;
}


int main(void)
{
        uint8_t ret;
        const struct device *uart_dev = device_get_binding(UART_DEVICE_NAME);
        if (!uart_dev) {
          printk("Cannot get UART device\n");
        }

        k_msleep(500);

        ret = verify_passwd(uart_dev);
        if(ret == 0) {
                printk("Verify Password Success\n");
        } else {
                printk("Error Occured 0x%X\n",ret);
        }

        k_msleep(500);

        ret = check_firmware(uart_dev);
        if(ret == 0) {
                printk("Firmware check Success\n");
        } else {
                printk("Error Occured 0x%X\n",ret);
        }

        k_msleep(500);

        ret = led_blue_ctrl(uart_dev);
        if(ret == 0) {
                printk("Blue LED Blinked on\n");
        } else {
                printk("Error Occured 0x%X\n",ret);
        }


  return 0;
}
