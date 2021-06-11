/* Automatically generated file; DO NOT EDIT */
/* Espressif IoT Development Framework Linker Script */
/* Generated from: /home/syafiq/esp_change/esp-idf/components/esp32/ld/esp32.project.ld.in */

/*  Default entry point:  */
ENTRY(call_start_cpu0);

SECTIONS
{
  /* RTC fast memory holds RTC wake stub code,
     including from any source file named rtc_wake_stub*.c
  */
  .rtc.text :
  {
    . = ALIGN(4);

    *(EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .rtc.literal EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .rtc.text EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .rtc.text.*)
    *libsoc.a:uart_hal_iram.*( .rtc.literal  .rtc.text  .rtc.text.*)

    *rtc_wake_stub*.*(.literal .text .literal.* .text.*)
    _rtc_text_end = ABSOLUTE(.);
  } > rtc_iram_seg

  /*
    This section is required to skip rtc.text area because rtc_iram_seg and
    rtc_data_seg are reflect the same address space on different buses.
  */
  .rtc.dummy :
  {
    _rtc_dummy_start = ABSOLUTE(.);
    _rtc_fast_start = ABSOLUTE(.);
    . = SIZEOF(.rtc.text);
    _rtc_dummy_end = ABSOLUTE(.);
  } > rtc_data_seg

  /* This section located in RTC FAST Memory area.
     It holds data marked with RTC_FAST_ATTR attribute.
     See the file "esp_attr.h" for more information.
  */
  .rtc.force_fast :
  {
    . = ALIGN(4);
    _rtc_force_fast_start = ABSOLUTE(.);
    *(.rtc.force_fast .rtc.force_fast.*)
    . = ALIGN(4) ;
    _rtc_force_fast_end = ABSOLUTE(.);
  } > rtc_data_seg

  /* RTC data section holds RTC wake stub
     data/rodata, including from any source file
     named rtc_wake_stub*.c and the data marked with
     RTC_DATA_ATTR, RTC_RODATA_ATTR attributes.
     The memory location of the data is dependent on
     CONFIG_ESP32_RTCDATA_IN_FAST_MEM option.
  */
  .rtc.data :
  {
    _rtc_data_start = ABSOLUTE(.);

    *(EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .rtc.data EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .rtc.data.* EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .rtc.rodata EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .rtc.rodata.*)
    *libsoc.a:uart_hal_iram.*( .rtc.data  .rtc.data.*  .rtc.rodata  .rtc.rodata.*)

    *rtc_wake_stub*.*(.data .rodata .data.* .rodata.* .bss .bss.*)
    _rtc_data_end = ABSOLUTE(.);
  } > rtc_data_location

  /* RTC bss, from any source file named rtc_wake_stub*.c */
  .rtc.bss (NOLOAD) :
  {
    _rtc_bss_start = ABSOLUTE(.);
    *rtc_wake_stub*.*(.bss .bss.*)
    *rtc_wake_stub*.*(COMMON)

    *(EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .rtc.bss)
    *libsoc.a:uart_hal_iram.*( .rtc.bss)

    _rtc_bss_end = ABSOLUTE(.);
  } > rtc_data_location

  /* This section holds data that should not be initialized at power up
     and will be retained during deep sleep.
     User data marked with RTC_NOINIT_ATTR will be placed
     into this section. See the file "esp_attr.h" for more information.
	 The memory location of the data is dependent on
     CONFIG_ESP32_RTCDATA_IN_FAST_MEM option.
  */
  .rtc_noinit (NOLOAD):
  {
    . = ALIGN(4);
    _rtc_noinit_start = ABSOLUTE(.);
    *(.rtc_noinit .rtc_noinit.*)
    . = ALIGN(4) ;
    _rtc_noinit_end = ABSOLUTE(.);
  } > rtc_data_location

  /* This section located in RTC SLOW Memory area.
     It holds data marked with RTC_SLOW_ATTR attribute.
     See the file "esp_attr.h" for more information.
  */
  .rtc.force_slow :
  {
    . = ALIGN(4);
    _rtc_force_slow_start = ABSOLUTE(.);
    *(.rtc.force_slow .rtc.force_slow.*)
    . = ALIGN(4) ;
    _rtc_force_slow_end = ABSOLUTE(.);
  } > rtc_slow_seg

  /* Get size of rtc slow data based on rtc_data_location alias */
  _rtc_slow_length = (ORIGIN(rtc_slow_seg) == ORIGIN(rtc_data_location))
                        ? (_rtc_force_slow_end - _rtc_data_start)
                        : (_rtc_force_slow_end - _rtc_force_slow_start);

  _rtc_fast_length = (ORIGIN(rtc_slow_seg) == ORIGIN(rtc_data_location))
                        ? (_rtc_force_fast_end - _rtc_fast_start)
                        : (_rtc_noinit_end - _rtc_fast_start);

  ASSERT((_rtc_slow_length <= LENGTH(rtc_slow_seg)),
          "RTC_SLOW segment data does not fit.")

  ASSERT((_rtc_fast_length <= LENGTH(rtc_data_seg)),
          "RTC_FAST segment data does not fit.")

  /* Send .iram0 code to iram */
  .iram0.vectors :
  {
    _iram_start = ABSOLUTE(.);
    /* Vectors go to IRAM */
    _init_start = ABSOLUTE(.);
    /* Vectors according to builds/RF-2015.2-win32/esp108_v1_2_s5_512int_2/config.html */
    . = 0x0;
    KEEP(*(.WindowVectors.text));
    . = 0x180;
    KEEP(*(.Level2InterruptVector.text));
    . = 0x1c0;
    KEEP(*(.Level3InterruptVector.text));
    . = 0x200;
    KEEP(*(.Level4InterruptVector.text));
    . = 0x240;
    KEEP(*(.Level5InterruptVector.text));
    . = 0x280;
    KEEP(*(.DebugExceptionVector.text));
    . = 0x2c0;
    KEEP(*(.NMIExceptionVector.text));
    . = 0x300;
    KEEP(*(.KernelExceptionVector.text));
    . = 0x340;
    KEEP(*(.UserExceptionVector.text));
    . = 0x3C0;
    KEEP(*(.DoubleExceptionVector.text));
    . = 0x400;
    *(.*Vector.literal)

    *(.UserEnter.literal);
    *(.UserEnter.text);
    . = ALIGN (16);
    *(.entry.text)
    *(.init.literal)
    *(.init)
    _init_end = ABSOLUTE(.);
  } > iram0_0_seg

  .iram0.text :
  {
    /* Code marked as runnning out of IRAM */
    _iram_text_start = ABSOLUTE(.);

    *(EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .iram1 EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .iram1.*)
    *libapp_trace.a:SEGGER_RTT_esp32.*( .literal  .literal.*  .text  .text.*)
    *libapp_trace.a:SEGGER_SYSVIEW.*( .literal  .literal.*  .text  .text.*)
    *libapp_trace.a:SEGGER_SYSVIEW_Config_FreeRTOS.*( .literal  .literal.*  .text  .text.*)
    *libapp_trace.a:SEGGER_SYSVIEW_FreeRTOS.*( .literal  .literal.*  .text  .text.*)
    *libapp_trace.a:app_trace.*( .literal  .literal.*  .text  .text.*)
    *libapp_trace.a:app_trace_util.*( .literal  .literal.*  .text  .text.*)
    *libesp32.a:panic.*( .literal  .literal.*  .text  .text.*)
    *libesp_event.a:default_event_loop.*(.literal.esp_event_isr_post .text.esp_event_isr_post)
    *libesp_event.a:esp_event.*(.literal.esp_event_isr_post_to .text.esp_event_isr_post_to)
    *libesp_ringbuf.a:( .literal  .literal.*  .text  .text.*)
    *libfreertos.a:( .literal  .literal.*  .text  .text.*)
    *libgcc.a:_divsf3.*( .literal  .literal.*  .text  .text.*)
    *libgcc.a:lib2funcs.*( .literal  .literal.*  .text  .text.*)
    *libgcov.a:( .literal  .literal.*  .text  .text.*)
    *libhal.a:( .literal  .literal.*  .text  .text.*)
    *libheap.a:multi_heap.*( .literal  .literal.*  .text  .text.*)
    *libheap.a:multi_heap_poisoning.*( .literal  .literal.*  .text  .text.*)
    *liblog.a:log.*(.literal.esp_log_write .text.esp_log_write)
    *liblog.a:log_freertos.*(.literal.esp_log_early_timestamp .text.esp_log_early_timestamp)
    *liblog.a:log_freertos.*(.literal.esp_log_impl_lock .text.esp_log_impl_lock)
    *liblog.a:log_freertos.*(.literal.esp_log_impl_lock_timeout .text.esp_log_impl_lock_timeout)
    *liblog.a:log_freertos.*(.literal.esp_log_impl_unlock .text.esp_log_impl_unlock)
    *liblog.a:log_freertos.*(.literal.esp_log_timestamp .text.esp_log_timestamp)
    *liblwip.a:api_lib.*(.literal.netconn_apimsg .text.netconn_apimsg)
    *liblwip.a:api_lib.*(.literal.netconn_recv .text.netconn_recv)
    *liblwip.a:api_lib.*(.literal.netconn_recv_data .text.netconn_recv_data)
    *liblwip.a:api_lib.*(.literal.netconn_recv_data_tcp .text.netconn_recv_data_tcp)
    *liblwip.a:api_lib.*(.literal.netconn_recv_tcp_pbuf_flags .text.netconn_recv_tcp_pbuf_flags)
    *liblwip.a:api_lib.*(.literal.netconn_recv_udp_raw_netbuf_flags .text.netconn_recv_udp_raw_netbuf_flags)
    *liblwip.a:api_lib.*(.literal.netconn_send .text.netconn_send)
    *liblwip.a:api_lib.*(.literal.netconn_sendto .text.netconn_sendto)
    *liblwip.a:api_lib.*(.literal.netconn_tcp_recvd .text.netconn_tcp_recvd)
    *liblwip.a:api_lib.*(.literal.netconn_tcp_recvd_msg .text.netconn_tcp_recvd_msg)
    *liblwip.a:api_lib.*(.literal.netconn_write_partly .text.netconn_write_partly)
    *liblwip.a:api_lib.*(.literal.netconn_write_vectors_partly .text.netconn_write_vectors_partly)
    *liblwip.a:api_msg.*(.literal.lwip_netconn_do_send .text.lwip_netconn_do_send)
    *liblwip.a:api_msg.*(.literal.lwip_netconn_do_write .text.lwip_netconn_do_write)
    *liblwip.a:etharp.*(.literal.etharp_output .text.etharp_output)
    *liblwip.a:etharp.*(.literal.etharp_output_to_arp_index .text.etharp_output_to_arp_index)
    *liblwip.a:ethernet.*(.literal.ethernet_input .text.ethernet_input)
    *liblwip.a:ethernet.*(.literal.ethernet_output .text.ethernet_output)
    *liblwip.a:ethernetif.*(.literal.ethernet_low_level_output .text.ethernet_low_level_output)
    *liblwip.a:ethernetif.*(.literal.ethernetif_input .text.ethernetif_input)
    *liblwip.a:inet_chksum.*(.literal.inet_chksum_pseudo .text.inet_chksum_pseudo)
    *liblwip.a:inet_chksum.*(.literal.inet_cksum_pseudo_base .text.inet_cksum_pseudo_base)
    *liblwip.a:ip4.*(.literal.ip4_input .text.ip4_input)
    *liblwip.a:ip4.*(.literal.ip4_output .text.ip4_output)
    *liblwip.a:ip4.*(.literal.ip4_output_if .text.ip4_output_if)
    *liblwip.a:ip4.*(.literal.ip4_output_if_opt .text.ip4_output_if_opt)
    *liblwip.a:ip4.*(.literal.ip4_output_if_opt_src .text.ip4_output_if_opt_src)
    *liblwip.a:ip4.*(.literal.ip4_output_if_src .text.ip4_output_if_src)
    *liblwip.a:ip4.*(.literal.ip4_route .text.ip4_route)
    *liblwip.a:ip4.*(.literal.ip4_route_src .text.ip4_route_src)
    *liblwip.a:ip4.*(.literal.ip4_route_src_hook .text.ip4_route_src_hook)
    *liblwip.a:ip4_addr.*(.literal.ip4_addr_isbroadcast_u32 .text.ip4_addr_isbroadcast_u32)
    *liblwip.a:netbuf.*(.literal.netbuf_alloc .text.netbuf_alloc)
    *liblwip.a:netbuf.*(.literal.netbuf_free .text.netbuf_free)
    *liblwip.a:pbuf.*(.literal.pbuf_add_header .text.pbuf_add_header)
    *liblwip.a:pbuf.*(.literal.pbuf_add_header_impl .text.pbuf_add_header_impl)
    *liblwip.a:pbuf.*(.literal.pbuf_alloc .text.pbuf_alloc)
    *liblwip.a:pbuf.*(.literal.pbuf_free .text.pbuf_free)
    *liblwip.a:pbuf.*(.literal.pbuf_header .text.pbuf_header)
    *liblwip.a:pbuf.*(.literal.pbuf_header_impl .text.pbuf_header_impl)
    *liblwip.a:pbuf.*(.literal.pbuf_remove_header .text.pbuf_remove_header)
    *liblwip.a:sockets.*(.literal.done_socket .text.done_socket)
    *liblwip.a:sockets.*(.literal.event_callback .text.event_callback)
    *liblwip.a:sockets.*(.literal.get_socket .text.get_socket)
    *liblwip.a:sockets.*(.literal.lwip_recv_tcp .text.lwip_recv_tcp)
    *liblwip.a:sockets.*(.literal.lwip_recv_tcp_from .text.lwip_recv_tcp_from)
    *liblwip.a:sockets.*(.literal.lwip_recvfrom .text.lwip_recvfrom)
    *liblwip.a:sockets.*(.literal.lwip_recvfrom_udp_raw .text.lwip_recvfrom_udp_raw)
    *liblwip.a:sockets.*(.literal.lwip_select .text.lwip_select)
    *liblwip.a:sockets.*(.literal.lwip_send .text.lwip_send)
    *liblwip.a:sockets.*(.literal.lwip_sendto .text.lwip_sendto)
    *liblwip.a:sockets.*(.literal.select_check_waiters .text.select_check_waiters)
    *liblwip.a:sockets.*(.literal.sock_inc_used .text.sock_inc_used)
    *liblwip.a:sockets.*(.literal.tryget_socket .text.tryget_socket)
    *liblwip.a:sockets.*(.literal.tryget_socket_unconn .text.tryget_socket_unconn)
    *liblwip.a:sockets.*(.literal.tryget_socket_unconn_locked .text.tryget_socket_unconn_locked)
    *liblwip.a:sockets.*(.literal.tryget_socket_unconn_nouse .text.tryget_socket_unconn_nouse)
    *liblwip.a:sys_arch.*(.literal.sys_arch_mbox_fetch .text.sys_arch_mbox_fetch)
    *liblwip.a:sys_arch.*(.literal.sys_arch_sem_wait .text.sys_arch_sem_wait)
    *liblwip.a:sys_arch.*(.literal.sys_mbox_post .text.sys_mbox_post)
    *liblwip.a:sys_arch.*(.literal.sys_mbox_trypost .text.sys_mbox_trypost)
    *liblwip.a:sys_arch.*(.literal.sys_mutex_lock .text.sys_mutex_lock)
    *liblwip.a:sys_arch.*(.literal.sys_mutex_unlock .text.sys_mutex_unlock)
    *liblwip.a:sys_arch.*(.literal.sys_sem_signal .text.sys_sem_signal)
    *liblwip.a:tcpip.*(.literal.tcpip_callback .text.tcpip_callback)
    *liblwip.a:tcpip.*(.literal.tcpip_inpkt .text.tcpip_inpkt)
    *liblwip.a:tcpip.*(.literal.tcpip_input .text.tcpip_input)
    *liblwip.a:tcpip.*(.literal.tcpip_send_msg_wait_sem .text.tcpip_send_msg_wait_sem)
    *liblwip.a:tcpip.*(.literal.tcpip_thread .text.tcpip_thread)
    *liblwip.a:tcpip.*(.literal.tcpip_thread_handle_msg .text.tcpip_thread_handle_msg)
    *liblwip.a:tcpip.*(.literal.tcpip_try_callback .text.tcpip_try_callback)
    *liblwip.a:timeouts.*(.literal.sys_timeouts_mbox_fetch .text.sys_timeouts_mbox_fetch)
    *liblwip.a:udp.*(.literal.udp_input .text.udp_input)
    *liblwip.a:udp.*(.literal.udp_input_local_match .text.udp_input_local_match)
    *liblwip.a:udp.*(.literal.udp_send .text.udp_send)
    *liblwip.a:udp.*(.literal.udp_sendto .text.udp_sendto)
    *liblwip.a:udp.*(.literal.udp_sendto_if .text.udp_sendto_if)
    *liblwip.a:udp.*(.literal.udp_sendto_if_src .text.udp_sendto_if_src)
    *liblwip.a:wlanif.*(.literal.low_level_output .text.low_level_output)
    *liblwip.a:wlanif.*(.literal.wlanif_input .text.wlanif_input)
    *libnet80211.a:( .wifi0iram  .wifi0iram.*)
    *libnet80211.a:( .wifirxiram  .wifirxiram.*)
    *libnewlib.a:heap.*( .literal  .literal.*  .text  .text.*)
    *libpp.a:( .wifi0iram  .wifi0iram.*)
    *libpp.a:( .wifirxiram  .wifirxiram.*)
    *librtc.a:( .literal  .literal.*  .text  .text.*)
    *libsoc.a:cpu_util.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:i2c_hal_iram.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:ledc_hal_iram.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:lldesc.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:rtc_clk.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:rtc_clk_init.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:rtc_init.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:rtc_periph.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:rtc_pm.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:rtc_sleep.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:rtc_time.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:rtc_wdt.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:spi_flash_hal_gpspi.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:spi_flash_hal_iram.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:spi_hal_iram.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:spi_slave_hal_iram.*( .literal  .literal.*  .text  .text.*)
    *libsoc.a:uart_hal_iram.*( .iram1  .iram1.*)
    *libspi_flash.a:memspi_host_driver.*( .literal  .literal.*  .text  .text.*)
    *libspi_flash.a:spi_flash_chip_gd.*( .literal  .literal.*  .text  .text.*)
    *libspi_flash.a:spi_flash_chip_generic.*( .literal  .literal.*  .text  .text.*)
    *libspi_flash.a:spi_flash_chip_issi.*( .literal  .literal.*  .text  .text.*)
    *libspi_flash.a:spi_flash_rom_patch.*( .literal  .literal.*  .text  .text.*)
    *libxtensa.a:eri.*( .literal  .literal.*  .text  .text.*)

    _iram_text_end = ABSOLUTE(.);
  } > iram0_0_seg

  .dram0.data :
  {
    _data_start = ABSOLUTE(.);
    _bt_data_start = ABSOLUTE(.);
    *libbt.a:(.data .data.*)
    . = ALIGN (4);
    _bt_data_end = ABSOLUTE(.);
    _btdm_data_start = ABSOLUTE(.);
    *libbtdm_app.a:(.data .data.*)
    . = ALIGN (4);
    _btdm_data_end = ABSOLUTE(.);
    _nimble_data_start = ABSOLUTE(.);
    *libnimble.a:(.data .data.*)
    . = ALIGN (4);
    _nimble_data_end = ABSOLUTE(.);
    *(.gnu.linkonce.d.*)
    *(.data1)
    *(.sdata)
    *(.sdata.*)
    *(.gnu.linkonce.s.*)
    *(.sdata2)
    *(.sdata2.*)
    *(.gnu.linkonce.s2.*)
    *(.jcr)


    *(EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .data EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .data.* EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .dram1 EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .dram1.*)
    *libapp_trace.a:SEGGER_RTT_esp32.*( .rodata  .rodata.*)
    *libapp_trace.a:SEGGER_SYSVIEW.*( .rodata  .rodata.*)
    *libapp_trace.a:SEGGER_SYSVIEW_Config_FreeRTOS.*( .rodata  .rodata.*)
    *libapp_trace.a:SEGGER_SYSVIEW_FreeRTOS.*( .rodata  .rodata.*)
    *libapp_trace.a:app_trace.*( .rodata  .rodata.*)
    *libapp_trace.a:app_trace_util.*( .rodata  .rodata.*)
    *libesp32.a:panic.*( .rodata  .rodata.*)
    *libesp_event.a:default_event_loop.*(.rodata.esp_event_isr_post)
    *libesp_event.a:esp_event.*(.rodata.esp_event_isr_post_to)
    *libgcc.a:_divsf3.*( .rodata  .rodata.*)
    *libgcov.a:( .rodata  .rodata.*)
    *libheap.a:multi_heap.*( .rodata  .rodata.*)
    *libheap.a:multi_heap_poisoning.*( .rodata  .rodata.*)
    *liblog.a:log.*(.rodata.esp_log_write)
    *liblog.a:log_freertos.*(.rodata.esp_log_early_timestamp)
    *liblog.a:log_freertos.*(.rodata.esp_log_impl_lock)
    *liblog.a:log_freertos.*(.rodata.esp_log_impl_lock_timeout)
    *liblog.a:log_freertos.*(.rodata.esp_log_impl_unlock)
    *liblog.a:log_freertos.*(.rodata.esp_log_timestamp)
    *libnewlib.a:heap.*( .rodata  .rodata.*)
    *libphy.a:( .rodata  .rodata.*)
    *libsoc.a:i2c_hal_iram.*( .rodata  .rodata.*)
    *libsoc.a:rtc_clk.*( .rodata  .rodata.*)
    *libsoc.a:spi_flash_hal_gpspi.*( .rodata  .rodata.*)
    *libsoc.a:spi_flash_hal_iram.*( .rodata  .rodata.*)
    *libsoc.a:uart_hal_iram.*( .data  .data.*  .dram1  .dram1.*)
    *libspi_flash.a:memspi_host_driver.*( .rodata  .rodata.*)
    *libspi_flash.a:spi_flash_chip_gd.*( .rodata  .rodata.*)
    *libspi_flash.a:spi_flash_chip_generic.*( .rodata  .rodata.*)
    *libspi_flash.a:spi_flash_chip_issi.*( .rodata  .rodata.*)

    _data_end = ABSOLUTE(.);
    . = ALIGN(4);
  } > dram0_0_seg

  /*This section holds data that should not be initialized at power up.
    The section located in Internal SRAM memory region. The macro _NOINIT
    can be used as attribute to place data into this section.
    See the esp_attr.h file for more information.
  */
  .noinit (NOLOAD):
  {
    . = ALIGN(4);
    _noinit_start = ABSOLUTE(.);
    *(.noinit .noinit.*)
    . = ALIGN(4) ;
    _noinit_end = ABSOLUTE(.);
  } > dram0_0_seg

  /* Shared RAM */
  .dram0.bss (NOLOAD) :
  {
    . = ALIGN (8);
    _bss_start = ABSOLUTE(.);
    *(.ext_ram.bss*)
    _bt_bss_start = ABSOLUTE(.);
    *libbt.a:(.bss .bss.* COMMON)
    . = ALIGN (4);
    _bt_bss_end = ABSOLUTE(.);
    _btdm_bss_start = ABSOLUTE(.);
    *libbtdm_app.a:(.bss .bss.* COMMON)
    . = ALIGN (4);
    _btdm_bss_end = ABSOLUTE(.);
    _nimble_bss_start = ABSOLUTE(.);
    *libnimble.a:(.bss .bss.* COMMON)
    . = ALIGN (4);
    _nimble_bss_end = ABSOLUTE(.);

    *(EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .bss EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) .bss.* EXCLUDE_FILE(*libsoc.a:uart_hal_iram.*) COMMON)
    *libsoc.a:uart_hal_iram.*( .bss  .bss.*  COMMON)

    *(.dynsbss)
    *(.sbss)
    *(.sbss.*)
    *(.gnu.linkonce.sb.*)
    *(.scommon)
    *(.sbss2)
    *(.sbss2.*)
    *(.gnu.linkonce.sb2.*)
    *(.dynbss)
    *(.share.mem)
    *(.gnu.linkonce.b.*)

    . = ALIGN (8);
    _bss_end = ABSOLUTE(.);
  } > dram0_0_seg

  ASSERT(((_bss_end - ORIGIN(dram0_0_seg)) <= LENGTH(dram0_0_seg)),
          "DRAM segment data does not fit.")

  .flash.rodata :
  {
    _rodata_start = ABSOLUTE(.);

    *(.rodata_desc .rodata_desc.*)               /* Should be the first.  App version info.        DO NOT PUT ANYTHING BEFORE IT! */
    *(.rodata_custom_desc .rodata_custom_desc.*) /* Should be the second. Custom app version info. DO NOT PUT ANYTHING BEFORE IT! */

    *(EXCLUDE_FILE(*libspi_flash.a:memspi_host_driver.* *libspi_flash.a:spi_flash_chip_issi.* *libspi_flash.a:spi_flash_chip_generic.* *libspi_flash.a:spi_flash_chip_gd.* *libesp32.a:panic.* *libgcc.a:_divsf3.* *libgcov.a *libsoc.a:i2c_hal_iram.* *libsoc.a:spi_flash_hal_iram.* *libsoc.a:uart_hal_iram.* *libsoc.a:rtc_clk.* *libsoc.a:spi_flash_hal_gpspi.* *libphy.a *libheap.a:multi_heap.* *libheap.a:multi_heap_poisoning.* *libnewlib.a:heap.* *libapp_trace.a:app_trace.* *libapp_trace.a:SEGGER_SYSVIEW_Config_FreeRTOS.* *libapp_trace.a:app_trace_util.* *libapp_trace.a:SEGGER_SYSVIEW_FreeRTOS.* *libapp_trace.a:SEGGER_SYSVIEW.* *libapp_trace.a:SEGGER_RTT_esp32.*) .rodata EXCLUDE_FILE(*libspi_flash.a:memspi_host_driver.* *libspi_flash.a:spi_flash_chip_issi.* *libspi_flash.a:spi_flash_chip_generic.* *libspi_flash.a:spi_flash_chip_gd.* *libesp32.a:panic.* *libgcc.a:_divsf3.* *libgcov.a *libsoc.a:i2c_hal_iram.* *libsoc.a:spi_flash_hal_iram.* *libsoc.a:uart_hal_iram.* *libsoc.a:rtc_clk.* *libsoc.a:spi_flash_hal_gpspi.* *libesp_event.a:esp_event.* *libesp_event.a:default_event_loop.* *libphy.a *liblog.a:log_freertos.* *liblog.a:log.* *libheap.a:multi_heap.* *libheap.a:multi_heap_poisoning.* *libnewlib.a:heap.* *libapp_trace.a:app_trace.* *libapp_trace.a:SEGGER_SYSVIEW_Config_FreeRTOS.* *libapp_trace.a:app_trace_util.* *libapp_trace.a:SEGGER_SYSVIEW_FreeRTOS.* *libapp_trace.a:SEGGER_SYSVIEW.* *libapp_trace.a:SEGGER_RTT_esp32.*) .rodata.*)
    *libesp_event.a:default_event_loop.*(.rodata.esp_event_loop_create_default.str1.4 .rodata.esp_event_send_to_default_loop)
    *libesp_event.a:esp_event.*(.rodata.handler_instances_add.str1.4 .rodata.base_node_add_handler.str1.4 .rodata.loop_node_add_handler.str1.4 .rodata.esp_event_loop_create.str1.4 .rodata.esp_event_loop_run.str1.4 .rodata.esp_event_loop_run_task.str1.4 .rodata.esp_event_handler_register_with.str1.4 .rodata.esp_event_handler_unregister_with.str1.4 .rodata.__func__$8605 .rodata.__func__$8592 .rodata.__func__$8572 .rodata.__func__$8556 .rodata.__func__$8533 .rodata.__func__$8492 .rodata.__func__$8483)
    *liblog.a:log.*(.rodata.esp_log_level_set.str1.4 .rodata.__func__$3534 .rodata.__func__$3505)
    *liblog.a:log_freertos.*(.rodata.esp_log_system_timestamp.str1.4)
    *libsoc.a:uart_hal_iram.*( .rodata  .rodata.*)

    *(.irom1.text) /* catch stray ICACHE_RODATA_ATTR */
    *(.gnu.linkonce.r.*)
    *(.rodata1)
    __XT_EXCEPTION_TABLE_ = ABSOLUTE(.);
    *(.xt_except_table)
    *(.gcc_except_table .gcc_except_table.*)
    *(.gnu.linkonce.e.*)
    *(.gnu.version_r)
    . = (. + 3) & ~ 3;
    __eh_frame = ABSOLUTE(.);
    KEEP(*(.eh_frame))
    . = (. + 7) & ~ 3;
    /*  C++ constructor and destructor tables

        Make a point of not including anything from crtbegin.o or crtend.o, as IDF doesn't use toolchain crt
      */
    __init_array_start = ABSOLUTE(.);
    KEEP (*(EXCLUDE_FILE (*crtend.* *crtbegin.*) .ctors .ctors.*))
    __init_array_end = ABSOLUTE(.);
    KEEP (*crtbegin.*(.dtors))
    KEEP (*(EXCLUDE_FILE (*crtend.*) .dtors))
    KEEP (*(SORT(.dtors.*)))
    KEEP (*(.dtors))
    /*  C++ exception handlers table:  */
    __XT_EXCEPTION_DESCS_ = ABSOLUTE(.);
    *(.xt_except_desc)
    *(.gnu.linkonce.h.*)
    __XT_EXCEPTION_DESCS_END__ = ABSOLUTE(.);
    *(.xt_except_desc_end)
    *(.dynamic)
    *(.gnu.version_d)
    /* Addresses of memory regions reserved via
       SOC_RESERVE_MEMORY_REGION() */
    soc_reserved_memory_region_start = ABSOLUTE(.);
    KEEP (*(.reserved_memory_address))
    soc_reserved_memory_region_end = ABSOLUTE(.);
    _rodata_end = ABSOLUTE(.);
    /* Literals are also RO data. */
    _lit4_start = ABSOLUTE(.);
    *(*.lit4)
    *(.lit4.*)
    *(.gnu.linkonce.lit4.*)
    _lit4_end = ABSOLUTE(.);
    . = ALIGN(4);
    _thread_local_start = ABSOLUTE(.);
    *(.tdata)
    *(.tdata.*)
    *(.tbss)
    *(.tbss.*)
    _thread_local_end = ABSOLUTE(.);
    . = ALIGN(4);
  } >default_rodata_seg

  .flash.text :
  {
    _stext = .;
    _text_start = ABSOLUTE(.);

    *(EXCLUDE_FILE(*libxtensa.a:eri.* *libhal.a *libesp_ringbuf.a *libspi_flash.a:spi_flash_rom_patch.* *libspi_flash.a:memspi_host_driver.* *libspi_flash.a:spi_flash_chip_issi.* *libspi_flash.a:spi_flash_chip_generic.* *libspi_flash.a:spi_flash_chip_gd.* *libesp32.a:panic.* *libgcc.a:lib2funcs.* *libgcc.a:_divsf3.* *libgcov.a *libsoc.a:rtc_time.* *libsoc.a:i2c_hal_iram.* *libsoc.a:cpu_util.* *libsoc.a:rtc_pm.* *libsoc.a:spi_flash_hal_iram.* *libsoc.a:ledc_hal_iram.* *libsoc.a:uart_hal_iram.* *libsoc.a:lldesc.* *libsoc.a:rtc_clk_init.* *libsoc.a:rtc_clk.* *libsoc.a:spi_flash_hal_gpspi.* *libsoc.a:rtc_periph.* *libsoc.a:spi_hal_iram.* *libsoc.a:rtc_sleep.* *libsoc.a:spi_slave_hal_iram.* *libsoc.a:rtc_init.* *libsoc.a:rtc_wdt.* *librtc.a *libheap.a:multi_heap.* *libheap.a:multi_heap_poisoning.* *libfreertos.a *libnewlib.a:heap.* *libapp_trace.a:app_trace.* *libapp_trace.a:SEGGER_SYSVIEW_Config_FreeRTOS.* *libapp_trace.a:app_trace_util.* *libapp_trace.a:SEGGER_SYSVIEW_FreeRTOS.* *libapp_trace.a:SEGGER_SYSVIEW.* *libapp_trace.a:SEGGER_RTT_esp32.*) .literal EXCLUDE_FILE(*libxtensa.a:eri.* *libhal.a *libesp_ringbuf.a *libspi_flash.a:spi_flash_rom_patch.* *libspi_flash.a:memspi_host_driver.* *libspi_flash.a:spi_flash_chip_issi.* *libspi_flash.a:spi_flash_chip_generic.* *libspi_flash.a:spi_flash_chip_gd.* *libesp32.a:panic.* *libgcc.a:lib2funcs.* *libgcc.a:_divsf3.* *libgcov.a *libsoc.a:rtc_time.* *libsoc.a:i2c_hal_iram.* *libsoc.a:cpu_util.* *libsoc.a:rtc_pm.* *libsoc.a:spi_flash_hal_iram.* *libsoc.a:ledc_hal_iram.* *libsoc.a:uart_hal_iram.* *libsoc.a:lldesc.* *libsoc.a:rtc_clk_init.* *libsoc.a:rtc_clk.* *libsoc.a:spi_flash_hal_gpspi.* *libsoc.a:rtc_periph.* *libsoc.a:spi_hal_iram.* *libsoc.a:rtc_sleep.* *libsoc.a:spi_slave_hal_iram.* *libsoc.a:rtc_init.* *libsoc.a:rtc_wdt.* *libesp_event.a:esp_event.* *libesp_event.a:default_event_loop.* *librtc.a *liblwip.a:timeouts.* *liblwip.a:api_msg.* *liblwip.a:etharp.* *liblwip.a:ip4_addr.* *liblwip.a:ethernetif.* *liblwip.a:wlanif.* *liblwip.a:udp.* *liblwip.a:netbuf.* *liblwip.a:sys_arch.* *liblwip.a:pbuf.* *liblwip.a:inet_chksum.* *liblwip.a:ethernet.* *liblwip.a:ip4.* *liblwip.a:tcpip.* *liblwip.a:sockets.* *liblwip.a:api_lib.* *liblog.a:log_freertos.* *liblog.a:log.* *libheap.a:multi_heap.* *libheap.a:multi_heap_poisoning.* *libfreertos.a *libnewlib.a:heap.* *libapp_trace.a:app_trace.* *libapp_trace.a:SEGGER_SYSVIEW_Config_FreeRTOS.* *libapp_trace.a:app_trace_util.* *libapp_trace.a:SEGGER_SYSVIEW_FreeRTOS.* *libapp_trace.a:SEGGER_SYSVIEW.* *libapp_trace.a:SEGGER_RTT_esp32.*) .literal.* EXCLUDE_FILE(*libxtensa.a:eri.* *libhal.a *libesp_ringbuf.a *libspi_flash.a:spi_flash_rom_patch.* *libspi_flash.a:memspi_host_driver.* *libspi_flash.a:spi_flash_chip_issi.* *libspi_flash.a:spi_flash_chip_generic.* *libspi_flash.a:spi_flash_chip_gd.* *libesp32.a:panic.* *libgcc.a:lib2funcs.* *libgcc.a:_divsf3.* *libgcov.a *libsoc.a:rtc_time.* *libsoc.a:i2c_hal_iram.* *libsoc.a:cpu_util.* *libsoc.a:rtc_pm.* *libsoc.a:spi_flash_hal_iram.* *libsoc.a:ledc_hal_iram.* *libsoc.a:uart_hal_iram.* *libsoc.a:lldesc.* *libsoc.a:rtc_clk_init.* *libsoc.a:rtc_clk.* *libsoc.a:spi_flash_hal_gpspi.* *libsoc.a:rtc_periph.* *libsoc.a:spi_hal_iram.* *libsoc.a:rtc_sleep.* *libsoc.a:spi_slave_hal_iram.* *libsoc.a:rtc_init.* *libsoc.a:rtc_wdt.* *librtc.a *libheap.a:multi_heap.* *libheap.a:multi_heap_poisoning.* *libfreertos.a *libnewlib.a:heap.* *libapp_trace.a:app_trace.* *libapp_trace.a:SEGGER_SYSVIEW_Config_FreeRTOS.* *libapp_trace.a:app_trace_util.* *libapp_trace.a:SEGGER_SYSVIEW_FreeRTOS.* *libapp_trace.a:SEGGER_SYSVIEW.* *libapp_trace.a:SEGGER_RTT_esp32.*) .text EXCLUDE_FILE(*libxtensa.a:eri.* *libhal.a *libesp_ringbuf.a *libspi_flash.a:spi_flash_rom_patch.* *libspi_flash.a:memspi_host_driver.* *libspi_flash.a:spi_flash_chip_issi.* *libspi_flash.a:spi_flash_chip_generic.* *libspi_flash.a:spi_flash_chip_gd.* *libesp32.a:panic.* *libgcc.a:lib2funcs.* *libgcc.a:_divsf3.* *libgcov.a *libsoc.a:rtc_time.* *libsoc.a:i2c_hal_iram.* *libsoc.a:cpu_util.* *libsoc.a:rtc_pm.* *libsoc.a:spi_flash_hal_iram.* *libsoc.a:ledc_hal_iram.* *libsoc.a:uart_hal_iram.* *libsoc.a:lldesc.* *libsoc.a:rtc_clk_init.* *libsoc.a:rtc_clk.* *libsoc.a:spi_flash_hal_gpspi.* *libsoc.a:rtc_periph.* *libsoc.a:spi_hal_iram.* *libsoc.a:rtc_sleep.* *libsoc.a:spi_slave_hal_iram.* *libsoc.a:rtc_init.* *libsoc.a:rtc_wdt.* *libesp_event.a:esp_event.* *libesp_event.a:default_event_loop.* *librtc.a *liblwip.a:timeouts.* *liblwip.a:api_msg.* *liblwip.a:etharp.* *liblwip.a:ip4_addr.* *liblwip.a:ethernetif.* *liblwip.a:wlanif.* *liblwip.a:udp.* *liblwip.a:netbuf.* *liblwip.a:sys_arch.* *liblwip.a:pbuf.* *liblwip.a:inet_chksum.* *liblwip.a:ethernet.* *liblwip.a:ip4.* *liblwip.a:tcpip.* *liblwip.a:sockets.* *liblwip.a:api_lib.* *liblog.a:log_freertos.* *liblog.a:log.* *libheap.a:multi_heap.* *libheap.a:multi_heap_poisoning.* *libfreertos.a *libnewlib.a:heap.* *libapp_trace.a:app_trace.* *libapp_trace.a:SEGGER_SYSVIEW_Config_FreeRTOS.* *libapp_trace.a:app_trace_util.* *libapp_trace.a:SEGGER_SYSVIEW_FreeRTOS.* *libapp_trace.a:SEGGER_SYSVIEW.* *libapp_trace.a:SEGGER_RTT_esp32.*) .text.* EXCLUDE_FILE(*libsoc.a:uart_hal_iram.* *libpp.a *libnet80211.a) .wifi0iram EXCLUDE_FILE(*libsoc.a:uart_hal_iram.* *libpp.a *libnet80211.a) .wifi0iram.* EXCLUDE_FILE(*libsoc.a:uart_hal_iram.* *libpp.a *libnet80211.a) .wifirxiram EXCLUDE_FILE(*libsoc.a:uart_hal_iram.* *libpp.a *libnet80211.a) .wifirxiram.*)
    *libesp_event.a:default_event_loop.*(.literal.esp_event_handler_register .literal.esp_event_handler_unregister .literal.esp_event_post .literal.esp_event_loop_create_default .literal.esp_event_loop_delete_default .literal.esp_event_send_to_default_loop .text.esp_event_handler_register .text.esp_event_handler_unregister .text.esp_event_post .text.esp_event_loop_create_default .text.esp_event_loop_delete_default .text.esp_event_send_to_default_loop)
    *libesp_event.a:esp_event.*(.literal.handler_instances_remove_all .literal.base_node_remove_all_handler .literal.loop_node_remove_all_handler .literal.handler_instances_add .literal.base_node_add_handler .literal.loop_node_add_handler .literal.handler_instances_remove .literal.base_node_remove_handler .literal.loop_node_remove_handler .literal.esp_event_loop_create .literal.esp_event_loop_run .literal.esp_event_loop_run_task .literal.esp_event_loop_delete .literal.esp_event_handler_register_with .literal.esp_event_handler_unregister_with .literal.esp_event_post_to .text.handler_execute .text.handler_instances_remove_all .text.base_node_remove_all_handler .text.loop_node_remove_all_handler .text.handler_instances_add .text.base_node_add_handler .text.loop_node_add_handler .text.handler_instances_remove .text.base_node_remove_handler .text.loop_node_remove_handler .text.esp_event_loop_create .text.esp_event_loop_run .text.esp_event_loop_run_task .text.esp_event_loop_delete .text.esp_event_handler_register_with .text.esp_event_handler_unregister_with .text.esp_event_post_to .text.esp_event_dump)
    *liblog.a:log.*(.literal.heap_bubble_down .literal.esp_log_set_vprintf .literal.esp_log_level_set .literal.esp_log_writev .text.heap_bubble_down .text.esp_log_set_vprintf .text.esp_log_level_set .text.esp_log_writev)
    *liblog.a:log_freertos.*(.literal.esp_log_system_timestamp .text.esp_log_system_timestamp)
    *liblwip.a:api_lib.*(.literal.netconn_close_shutdown .literal.netconn_new_with_proto_and_callback .literal.netconn_prepare_delete .literal.netconn_delete .literal.netconn_getaddr .literal.netconn_bind .literal.netconn_bind_if .literal.netconn_connect .literal.netconn_disconnect .literal.netconn_listen_with_backlog .literal.netconn_close .literal.netconn_err .literal.netconn_accept .literal.netconn_recv_udp_raw_netbuf .literal.netconn_recv_tcp_pbuf .literal.netconn_shutdown .literal.netconn_join_leave_group .literal.netconn_join_leave_group_netif .literal.netconn_gethostbyname_addrtype .literal.netconn_thread_init .literal.netconn_thread_cleanup .text.netconn_close_shutdown .text.netconn_new_with_proto_and_callback .text.netconn_prepare_delete .text.netconn_delete .text.netconn_getaddr .text.netconn_bind .text.netconn_bind_if .text.netconn_connect .text.netconn_disconnect .text.netconn_listen_with_backlog .text.netconn_close .text.netconn_err .text.netconn_accept .text.netconn_recv_udp_raw_netbuf .text.netconn_recv_tcp_pbuf .text.netconn_shutdown .text.netconn_join_leave_group .text.netconn_join_leave_group_netif .text.netconn_gethostbyname_addrtype .text.netconn_thread_init .text.netconn_thread_cleanup)
    *liblwip.a:api_msg.*(.literal.lwip_netconn_err_to_msg .literal.lwip_netconn_do_dns_found .literal.recv_udp .literal.recv_raw .literal.setup_tcp .literal.pcb_new .literal.lwip_netconn_do_connected .literal.err_tcp .literal.netconn_mark_mbox_invalid .literal.lwip_netconn_do_writemore .literal.lwip_netconn_do_close_internal .literal.poll_tcp .literal.sent_tcp .literal.recv_tcp .literal.lwip_netconn_is_deallocated_msg .literal.lwip_netconn_is_err_msg .literal.lwip_netconn_do_newconn .literal.netconn_alloc .literal.netconn_free .literal.netconn_drain .literal.accept_function .literal.lwip_netconn_do_delconn .literal.lwip_netconn_do_bind .literal.lwip_netconn_do_bind_if .literal.lwip_netconn_do_connect .literal.lwip_netconn_do_disconnect .literal.lwip_netconn_do_listen .literal.lwip_netconn_do_recv .literal.lwip_netconn_do_accepted .literal.lwip_netconn_do_getaddr .literal.lwip_netconn_do_close .literal.lwip_netconn_do_join_leave_group .literal.lwip_netconn_do_join_leave_group_netif .literal.lwip_netconn_do_gethostbyname .text.lwip_netconn_err_to_msg .text.lwip_netconn_do_dns_found .text.recv_udp .text.recv_raw .text.setup_tcp .text.pcb_new .text.lwip_netconn_do_connected .text.err_tcp .text.netconn_mark_mbox_invalid .text.lwip_netconn_do_writemore .text.lwip_netconn_do_close_internal .text.poll_tcp .text.sent_tcp .text.recv_tcp .text.lwip_netconn_is_deallocated_msg .text.lwip_netconn_is_err_msg .text.lwip_netconn_do_newconn .text.netconn_alloc .text.netconn_free .text.netconn_drain .text.accept_function .text.lwip_netconn_do_delconn .text.lwip_netconn_do_bind .text.lwip_netconn_do_bind_if .text.lwip_netconn_do_connect .text.lwip_netconn_do_disconnect .text.lwip_netconn_do_listen .text.lwip_netconn_do_recv .text.lwip_netconn_do_accepted .text.lwip_netconn_do_getaddr .text.lwip_netconn_do_close .text.lwip_netconn_do_join_leave_group .text.lwip_netconn_do_join_leave_group_netif .text.lwip_netconn_do_gethostbyname)
    *liblwip.a:etharp.*(.literal.free_etharp_q .literal.etharp_free_entry .literal.etharp_find_entry .literal.etharp_update_arp_entry .literal.etharp_raw .literal.etharp_request_dst .literal.etharp_cleanup_netif .literal.etharp_find_addr .literal.etharp_get_entry .literal.etharp_input .literal.etharp_request .literal.garp_tmr .literal.etharp_tmr .literal.etharp_query .text.free_etharp_q .text.etharp_free_entry .text.etharp_find_entry .text.etharp_update_arp_entry .text.etharp_raw .text.etharp_request_dst .text.etharp_cleanup_netif .text.etharp_find_addr .text.etharp_get_entry .text.etharp_input .text.etharp_request .text.garp_tmr .text.etharp_tmr .text.etharp_query)
    *liblwip.a:ethernet.*( .literal.*  .text.*)
    *liblwip.a:ethernetif.*(.literal.ethernet_free_rx_buf_l2 .literal.ethernetif_init .text.ethernet_low_level_init .text.ethernet_free_rx_buf_l2 .text.ethernetif_init)
    *liblwip.a:inet_chksum.*(.literal.inet_cksum_pseudo_partial_base .literal.ip6_chksum_pseudo .literal.ip_chksum_pseudo .literal.inet_chksum_pseudo_partial .literal.ip6_chksum_pseudo_partial .literal.ip_chksum_pseudo_partial .literal.inet_chksum .literal.inet_chksum_pbuf .text.lwip_standard_chksum .text.inet_cksum_pseudo_partial_base .text.ip6_chksum_pseudo .text.ip_chksum_pseudo .text.inet_chksum_pseudo_partial .text.ip6_chksum_pseudo_partial .text.ip_chksum_pseudo_partial .text.inet_chksum .text.inet_chksum_pbuf)
    *liblwip.a:ip4.*(.literal.ip4_input_accept .literal.ip4_set_default_multicast_netif .literal.ip4_netif_exist .text.ip4_input_accept .text.ip4_set_default_multicast_netif .text.ip4_netif_exist)
    *liblwip.a:ip4_addr.*(.literal.ip4_addr_netmask_valid .literal.ip4addr_aton .literal.ipaddr_addr .literal.ip4addr_ntoa_r .literal.ip4addr_ntoa .text.ip4_addr_netmask_valid .text.ip4addr_aton .text.ipaddr_addr .text.ip4addr_ntoa_r .text.ip4addr_ntoa)
    *liblwip.a:netbuf.*(.literal.netbuf_new .literal.netbuf_delete .literal.netbuf_ref .literal.netbuf_chain .literal.netbuf_data .literal.netbuf_next .literal.netbuf_first .text.netbuf_new .text.netbuf_delete .text.netbuf_ref .text.netbuf_chain .text.netbuf_data .text.netbuf_next .text.netbuf_first)
    *liblwip.a:pbuf.*(.literal.pbuf_pool_is_empty .literal.pbuf_free_ooseq .literal.pbuf_free_ooseq_callback .literal.pbuf_alloc_reference .literal.pbuf_alloced_custom .literal.pbuf_add_header_force .literal.pbuf_header_force .literal.pbuf_realloc .literal.pbuf_free_header .literal.pbuf_ref .literal.pbuf_cat .literal.pbuf_chain .literal.pbuf_dechain .literal.pbuf_copy .literal.pbuf_copy_partial .literal.pbuf_get_contiguous .literal.pbuf_skip .literal.pbuf_take .literal.pbuf_take_at .literal.pbuf_clone .literal.pbuf_coalesce .literal.pbuf_try_get_at .literal.pbuf_get_at .literal.pbuf_put_at .literal.pbuf_memcmp .literal.pbuf_memfind .literal.pbuf_strstr .text.pbuf_init_alloced_pbuf .text.pbuf_skip_const .text.pbuf_pool_is_empty .text.pbuf_free_ooseq .text.pbuf_free_ooseq_callback .text.pbuf_alloc_reference .text.pbuf_alloced_custom .text.pbuf_add_header_force .text.pbuf_header_force .text.pbuf_realloc .text.pbuf_free_header .text.pbuf_clen .text.pbuf_ref .text.pbuf_cat .text.pbuf_chain .text.pbuf_dechain .text.pbuf_copy .text.pbuf_copy_partial .text.pbuf_get_contiguous .text.pbuf_skip .text.pbuf_take .text.pbuf_take_at .text.pbuf_clone .text.pbuf_coalesce .text.pbuf_try_get_at .text.pbuf_get_at .text.pbuf_put_at .text.pbuf_memcmp .text.pbuf_memfind .text.pbuf_strstr)
    *liblwip.a:sockets.*(.literal.free_socket_locked .literal.lwip_sockopt_to_ipopt .literal.lwip_link_select_cb .literal.lwip_unlink_select_cb .literal.sockaddr_to_ipaddr_port .literal.lwip_sock_make_addr .literal.lwip_poll_inc_sockets_used .literal.sock_inc_used_locked .literal.lwip_select_inc_sockets_used_set .literal.lwip_select_inc_sockets_used .literal.alloc_socket .literal.free_socket_free_elements .literal.free_socket .literal.lwip_selscan .literal.lwip_select_dec_sockets_used .literal.lwip_pollscan .literal.lwip_poll_dec_sockets_used .literal.lwip_getaddrname .literal.lwip_socket_register_membership .literal.lwip_socket_unregister_membership .literal.lwip_socket_register_mld6_membership .literal.lwip_socket_unregister_mld6_membership .literal.lwip_socket_drop_registered_memberships .literal.lwip_socket_drop_registered_mld6_memberships .literal.lwip_getsockopt_impl .literal.lwip_getsockopt_callback .literal.lwip_setsockopt_impl .literal.lwip_setsockopt_callback .literal.lwip_socket_thread_init .literal.lwip_socket_thread_cleanup .literal.lwip_socket_dbg_get_socket .literal.lwip_accept .literal.lwip_bind .literal.lwip_close .literal.lwip_connect .literal.lwip_listen .literal.lwip_read .literal.lwip_recv .literal.lwip_recvmsg .literal.lwip_readv .literal.lwip_sendmsg .literal.lwip_socket .literal.lwip_write .literal.lwip_writev .literal.lwip_poll .literal.lwip_shutdown .literal.lwip_getpeername .literal.lwip_getsockname .literal.lwip_getsockopt .literal.lwip_setsockopt .literal.lwip_ioctl .literal.lwip_fcntl .literal.lwip_inet_ntop .literal.lwip_inet_pton .text.lwip_poll_should_wake .text.free_socket_locked .text.lwip_sockopt_to_ipopt .text.lwip_link_select_cb .text.lwip_unlink_select_cb .text.sockaddr_to_ipaddr_port .text.lwip_sock_make_addr .text.lwip_poll_inc_sockets_used .text.sock_inc_used_locked .text.lwip_select_inc_sockets_used_set .text.lwip_select_inc_sockets_used .text.alloc_socket .text.free_socket_free_elements .text.free_socket .text.lwip_selscan .text.lwip_select_dec_sockets_used .text.lwip_pollscan .text.lwip_poll_dec_sockets_used .text.lwip_getaddrname .text.lwip_socket_register_membership .text.lwip_socket_unregister_membership .text.lwip_socket_register_mld6_membership .text.lwip_socket_unregister_mld6_membership .text.lwip_socket_drop_registered_memberships .text.lwip_socket_drop_registered_mld6_memberships .text.lwip_getsockopt_impl .text.lwip_getsockopt_callback .text.lwip_setsockopt_impl .text.lwip_setsockopt_callback .text.lwip_socket_thread_init .text.lwip_socket_thread_cleanup .text.lwip_socket_dbg_get_socket .text.lwip_accept .text.lwip_bind .text.lwip_close .text.lwip_connect .text.lwip_listen .text.lwip_read .text.lwip_recv .text.lwip_recvmsg .text.lwip_readv .text.lwip_sendmsg .text.lwip_socket .text.lwip_write .text.lwip_writev .text.lwip_poll .text.lwip_shutdown .text.lwip_getpeername .text.lwip_getsockname .text.lwip_getsockopt .text.lwip_setsockopt .text.lwip_ioctl .text.lwip_fcntl .text.lwip_inet_ntop .text.lwip_inet_pton)
    *liblwip.a:sys_arch.*(.literal.sys_thread_sem_free .literal.sys_mutex_new .literal.sys_mutex_free .literal.sys_sem_new .literal.sys_sem_signal_isr .literal.sys_sem_free .literal.sys_mbox_new .literal.sys_mbox_trypost_fromisr .literal.sys_arch_mbox_tryfetch .literal.sys_mbox_free .literal.sys_thread_new .literal.sys_init .literal.sys_jiffies .literal.sys_now .literal.sys_arch_protect .literal.sys_arch_unprotect .literal.sys_thread_sem_init .literal.sys_thread_sem_get .literal.sys_thread_sem_deinit .literal.sys_delay_ms .text.sys_thread_sem_free .text.sys_mutex_new .text.sys_mutex_free .text.sys_sem_new .text.sys_sem_signal_isr .text.sys_sem_free .text.sys_mbox_new .text.sys_mbox_trypost_fromisr .text.sys_arch_mbox_tryfetch .text.sys_mbox_set_owner .text.sys_mbox_free .text.sys_thread_new .text.sys_init .text.sys_jiffies .text.sys_now .text.sys_arch_protect .text.sys_arch_unprotect .text.sys_thread_sem_init .text.sys_thread_sem_get .text.sys_thread_sem_deinit .text.sys_delay_ms)
    *liblwip.a:tcpip.*(.literal.tcpip_timeouts_mbox_fetch .literal.pbuf_free_int .literal.tcpip_api_call .literal.tcpip_callbackmsg_new .literal.tcpip_callbackmsg_delete .literal.tcpip_callbackmsg_trycallback .literal.tcpip_callbackmsg_trycallback_fromisr .literal.tcpip_init .literal.pbuf_free_callback .literal.mem_free_callback .text.tcpip_timeouts_mbox_fetch .text.pbuf_free_int .text.tcpip_api_call .text.tcpip_callbackmsg_new .text.tcpip_callbackmsg_delete .text.tcpip_callbackmsg_trycallback .text.tcpip_callbackmsg_trycallback_fromisr .text.tcpip_init .text.pbuf_free_callback .text.mem_free_callback)
    *liblwip.a:timeouts.*(.literal.sys_timeout_abs .literal.lwip_cyclic_timer .literal.sys_timeout .literal.tcp_timer_needed .literal.tcpip_tcp_timer .literal.sys_timeouts_init .literal.sys_untimeout .literal.sys_check_timeouts .literal.sys_restart_timeouts .literal.sys_timeouts_sleeptime .text.sys_timeout_abs .text.lwip_cyclic_timer .text.sys_timeout .text.tcp_timer_needed .text.tcpip_tcp_timer .text.sys_timeouts_init .text.sys_untimeout .text.sys_check_timeouts .text.sys_restart_timeouts .text.sys_timeouts_sleeptime)
    *liblwip.a:udp.*(.literal.udp_new_port .literal.udp_init .literal.udp_bind .literal.udp_connect .literal.udp_disconnect .literal.udp_recv .literal.udp_remove .literal.udp_new .literal.udp_new_ip_type .literal.udp_netif_ip_addr_changed .text.udp_new_port .text.udp_init .text.udp_bind .text.udp_bind_netif .text.udp_connect .text.udp_disconnect .text.udp_recv .text.udp_remove .text.udp_new .text.udp_new_ip_type .text.udp_netif_ip_addr_changed)
    *liblwip.a:wlanif.*(.literal.low_level_init .literal.lwip_netif_wifi_free_rx_buffer .literal.wlanif_init .literal.wlanif_init_sta .literal.wlanif_init_ap .text.low_level_init .text.lwip_netif_wifi_free_rx_buffer .text.wlanif_init .text.wlanif_init_sta .text.wlanif_init_ap)
    *libsoc.a:uart_hal_iram.*( .literal  .literal.*  .text  .text.*  .wifi0iram  .wifi0iram.*  .wifirxiram  .wifirxiram.*)

    *(.stub .gnu.warning .gnu.linkonce.literal.* .gnu.linkonce.t.*.literal .gnu.linkonce.t.*)
    *(.irom0.text) /* catch stray ICACHE_RODATA_ATTR */
    *(.fini.literal)
    *(.fini)
    *(.gnu.version)
    _text_end = ABSOLUTE(.);
    _etext = .;

    /* Similar to _iram_start, this symbol goes here so it is
       resolved by addr2line in preference to the first symbol in
       the flash.text segment.
    */
    _flash_cache_start = ABSOLUTE(0);
  } >default_code_seg

  /* Marks the end of IRAM code segment */
  .iram0.text_end (NOLOAD) :
  {
    . = ALIGN (4);
    _iram_end = ABSOLUTE(.);
  } > iram0_0_seg

  /* Marks the end of data, bss and possibly rodata  */
  .dram0.heap_start (NOLOAD) :
  {
    . = ALIGN (8);
    _heap_start = ABSOLUTE(.);
  } > dram0_0_seg
}

ASSERT(((_iram_text_end - ORIGIN(iram0_0_seg)) <= LENGTH(iram0_0_seg)),
          "IRAM0 segment data does not fit.")

ASSERT(((_heap_start - ORIGIN(dram0_0_seg)) <= LENGTH(dram0_0_seg)),
          "DRAM segment data does not fit.")
