/*
 * Простой сетевой тест "UDP Ping-Pong"
 * Версия: 0.1a
 * Файл: "pong.c"
 * Кодировка: UTF-8
 * Автор: Александр Гриньков <a.grinkov@gmail.com>
 * (C) 2015 ОАО "НИИ приборостроения им. В.В. Тихомирова"
 * Дата модификации: 2015.09.09
 */

//-----------------------------------------------------------------------------
//#include <math.h>
#include <stdlib.h>   // exit(), EXIT_SUCCESS, EXIT_FAILURE, atoi()
#include <string.h>   // strcmp()
//#include <unistd.h>
#include <stdio.h>    // fprintf(), printf(), perror()
#include <string.h>   // memset()
#include <signal.h>   // sigaction(),  sigemptyset(), sigprocmask()
#include <time.h>     // clock_gettime(), clock_getres(), time_t, ...
#include <sched.h>    // sched_setscheduler(), SCHED_FIFO, ...
//-----------------------------------------------------------------------------
#include "socklib.h"
//#include "gtime.h"
//-----------------------------------------------------------------------------
// используемый таймер
// CLOCK_REALTIME CLOCK_MONOTONIC
// CLOCK_PROCESS_CPUTIME_ID CLOCK_THREAD_CPUTIME_ID (since Linux 2.6.12)
// CLOCK_REALTIME_HR CLOCK_MONOTONIC_HR (MontaVista)
#define CLOCKID CLOCK_REALTIME
//-----------------------------------------------------------------------------
// сигнал таймера
#define SIG SIGRTMIN
//-----------------------------------------------------------------------------
// максимальный размер пакета
#define MAX_SIZE 10000
//-----------------------------------------------------------------------------
// первое магическое 32-битное слово в передаваемых пакетах (сигнатура)
#define PING_MAGIC 0x01020304
#define PONG_MAGIC 0x0FF055AA
//-----------------------------------------------------------------------------
#define err_exit(msg) \
  do { perror("Error: " msg); exit(EXIT_FAILURE); } while (0)
//-----------------------------------------------------------------------------
static void usage()
{
  fprintf(stderr,
    "This is simple network tester based on 'UDP Ping-Pong'.\n"
    "Usage: pong -e [-options]\n"
    "       pong    [-options] [remote_host]\n"
    "       pong --help\n");
  exit(EXIT_FAILURE);
}
//-----------------------------------------------------------------------------
static void help()
{
  printf(
    "This is simple network tester based on 'UDP Ping-Pong'.\n"
    "Run in echo mode:    pong -e [-options]\n"
    "Run in sender mode:  pong    [-options] hostname\n"
    "Options:\n"
    "   -h|--help              show this help\n"
    "   -v|--verbose           verbose output\n"
    "  -vv|--more-verbose      more verbose output (or use -v twice)\n"
    "   -d|--data              output packet statistic to stdout (no verbose)\n"
    "   -s|--server            run in server mode\n"
    "   -l|--listen-ip ip      listen IP address (by default 0.0.0.0)\n"
    "   -p|--port port         UDP port (by default 7777)\n"
    "   -i|--interval ms       sender interrval [ms] (by default 1000)\n"
    "   -t|--timeout ms        wait packet timeout [ms] (by default 1000)\n"
    "   -z|--packet-size size  UDP packet size [bytes>=24] (by default 1000)\n"
    "   -c|--packet-count cnt  packet counter (by default 0 - infinity)\n"
    "   -r|--real-time         real time mode (root required)\n"
    "By default remote hostname is 127.0.0.1 for loop debug.\n");
  exit(EXIT_SUCCESS);
}
//-----------------------------------------------------------------------------
// options
static const char *hostname   = "127.0.0.1"; // remote host IP address
static const char *listen_ip  = "0.0.0.0";   // listen IP address
static int           verbose  = 1;    // verbose level {0,1,2,3}
static int         echo_mode  = 0;    // echo mode if non zero
static int          udp_port  = 7777; // UDP port
static int       interval_ms  = 1000; // send interval [ms]
static int       timeout_ms   = 1000; // timeout [ms]
static int       packet_size  = 1000; // packet size [bytes]
static int       packet_count = 0;    // packet counter
static int       data_stdout  = 0;    // output statistic to stdout
//-----------------------------------------------------------------------------
// global variable
static int sock; // UDP BSD socket

// send/receive buffers
static uint32_t send_buf[(MAX_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
static uint32_t recv_buf[(MAX_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];

unsigned overrun = 0; // FIXME

unsigned lost_count = 0; // счетчик потерянных пакетов

int stop_flag = 0; // set to 1 if Ctrl-C pressed

uint32_t counter = 1; // packet send/recive counter

int realtime = 0; // real time mode
//-----------------------------------------------------------------------------
// parse command options
static void parse_options(int argc, const char *argv[])
{
  int i;
  for (i = 1; i < argc; i++)
  {
    if (argv[i][0] == '-')
    { // parse options
      if (!strcmp(argv[i], "-h") ||
          !strcmp(argv[i], "--help"))
      { // print help
        help();
      }
      else if (!strcmp(argv[i], "-v") ||
               !strcmp(argv[i], "--verbose"))
      { // verbose level 1
        verbose++;
        data_stdout = 0;
      }
      else if (!strcmp(argv[i], "-vv") ||
               !strcmp(argv[i], "--more-verbose"))
      { // verbode level 2
        verbose = 3;
        data_stdout = 0;
      }
      else if (!strcmp(argv[i], "-d") ||
               !strcmp(argv[i], "--data"))
      { // output packet statistic to stdout
        verbose = 0;
        data_stdout = 1;
      }
      else if (!strcmp(argv[i], "-s") ||
               !strcmp(argv[i], "--server"))
      { // echo mode
        echo_mode = 1;
      }
      else if (!strcmp(argv[i], "-l") ||
               !strcmp(argv[i], "--listen-ip"))
      { // echo mode
        if (++i >= argc) usage();
        echo_mode = 1;
        listen_ip = argv[i];
      }
      else if (!strcmp(argv[i], "-p") ||
               !strcmp(argv[i], "--port"))
      { // UDP port
        if (++i >= argc) usage();
        udp_port = atoi(argv[i]);
        if (udp_port <= 0 || udp_port >= 65536) usage();
      }
      else if (!strcmp(argv[i], "-i") ||
               !strcmp(argv[i], "--interval"))
      { // interval [ms]
        if (++i >= argc) usage();
        interval_ms = atoi(argv[i]);
        if (interval_ms < 0) usage();
      }
      else if (!strcmp(argv[i], "-t") ||
               !strcmp(argv[i], "--timeout"))
      { // timeout [ms]
        if (++i >= argc) usage();
        timeout_ms = atoi(argv[i]);
        if (timeout_ms <= 0) usage();
      }
      else if (!strcmp(argv[i], "-z") ||
               !strcmp(argv[i], "--packet-size"))
      { // packet size [bytes]
        if (++i >= argc) usage();
        packet_size = atoi(argv[i]);
        if (packet_size <= 0) usage();
        if (packet_size < 3*sizeof(uint32_t)) packet_size = 3*sizeof(uint32_t);
        if (packet_size > MAX_SIZE) packet_size = MAX_SIZE;
      }
      else if (!strcmp(argv[i], "-c") ||
               !strcmp(argv[i], "--packet-count"))
      { // packet counter
        if (++i >= argc) usage();
        packet_count = atoi(argv[i]);
        if (packet_count < 0) usage();
      }
      else if (!strcmp(argv[i], "-r") ||
               !strcmp(argv[i], "--real-time"))
      { // real time mode
        realtime = 1;
      }
      else
        usage();
    }
    else
    { // parse hostname
      hostname = argv[i];
    }
  } // for
}
//-----------------------------------------------------------------------------
// set the process to real-time privs
static void set_realtime_priority()
{
  struct sched_param schp;
  memset(&schp, 0, sizeof(schp));
  schp.sched_priority = sched_get_priority_max(SCHED_FIFO);

  if (sched_setscheduler(0, SCHED_FIFO, &schp) != 0)
    err_exit("sched_setscheduler(SCHED_FIFO)");
}
//-----------------------------------------------------------------------------
// вернуть время суток (цена младшего разряда 24*60*60/2**32)
static uint32_t get_daytime()
{
  struct timespec ts;
  struct tm tm;
  time_t time;
  double t;

  //clock_gettime(CLOCK_REALTIME, &ts);
  clock_gettime(CLOCK_MONOTONIC, &ts);

  time = (time_t) ts.tv_sec;
  localtime_r(&time, &tm);
  time = tm.tm_sec + tm.tm_min * 60 + tm.tm_hour * 3600;

  t  = ((double) ts.tv_nsec) * 1e-9;
  t += ((double) time);
  t *= (4294967296. / (24.*60.*60.));

  return (uint32_t) t;
}
//-----------------------------------------------------------------------------
// перевести суточное время в секунды [0..24h]
static double daytime_to_sec(uint32_t daytime)
{
  double t = (double) daytime;
  return t * ((24.*60.*60.) / 4294967296.);
}
//-----------------------------------------------------------------------------
// перевести разницу суточного времени в секунды [12...12h]
static double deltatime_to_sec(int32_t delta_daytime)
{
  double t = (double) delta_daytime;
  return t * ((24.*60.*60.) / 4294967296.);
}
//-----------------------------------------------------------------------------
// перевести разницу суточного времени в мс
static int deltatime_to_ms(int32_t delta_daytime)
{
  double t = (double) delta_daytime;
  return (int) (t * ((24.*60.*60.*1000.) / 4294967296.));
}
//-----------------------------------------------------------------------------
// преобразовать время из double [sec] в `struct timespec`
static struct timespec double_to_ts(double t)
{
  struct timespec ts;
  ts.tv_sec  = (time_t) t;
  ts.tv_nsec = (long) ((t - (double) ts.tv_sec) * 1e9);
  return ts;
}
//-----------------------------------------------------------------------------
// распечатать суточное время в формате HH:MM:SS.mmmuuu
static void print_daytime(uint32_t daytime)
{
  unsigned h, m, s, us;
  double t = (double) daytime;
  t *= ((24.*60.*60.) / 4294967296.); // to seconds
  s = (unsigned) t;
  h =  s / 3600;     // часы
  m = (s / 60) % 60; // минуты
  s =  s       % 60; // секунды
  t -= (double) (h * 3600 + m * 60 + s);
  us = (unsigned) (t * 1e6);
  printf("%02u:%02u:%02u.%06u", h, m, s, us);
}
//-----------------------------------------------------------------------------
// функция приемника (UDP server)
static void receiver()
{
  int retv;
  unsigned ip_addr;   // IP address of sender
  uint32_t recv_time; // время приема предыдущего пакета
  int32_t delta_time; // время между приходом соседних пакетов
  int port;           // порт отправителя
  int ans_size;       // размер ответного пакета

  if (verbose >= 2)
  {
    printf("PONG run in echo (UDP server) mode:\n");
    printf("  listen_ip     = %s\n", listen_ip);
    printf("  udp_port      = %i\n", udp_port);
    printf("  packet_count  = %i\n", packet_count);
    printf("  verbose level = %i\n", verbose);
    printf("  real time     = %s\n", realtime ? "yes" : "no");
  }

  // make server UDP socket
  sock = sl_udp_make_server_socket_ex(listen_ip, udp_port);
  if (sock < 0)
  {
    fprintf(stderr, "Error in sl_udp_make_server_socket_ex(): '%s'; exit\n",
            sl_error_str(sock));
    exit(EXIT_FAILURE);
  }

  // ждать пакеты и отвечать
  recv_time = (uint32_t) -1;
  delta_time = 0;
  for (;;)
  {
    uint32_t daytime; // текущее время приема пакета

    if (stop_flag)
    { // Ctrl-C pressed
      fprintf(stderr, "\nCtrl-C pressed; exit\n");
      counter--;
      break;
    }

    // read datagram from UDP socket (timeout)
    retv = sl_udp_read_to(sock, recv_buf, sizeof(recv_buf),
                          &ip_addr, &port, timeout_ms);
    if (retv == SL_TIMEOUT)
    {
      if (verbose >= 2)
        printf("Receive UDP packet #%u timeout; continue\n", counter);
      continue;
    }
    else if (retv < 0)
    {
      fprintf(stderr, "Error in sl_udp_read(): '%s'; exit\n",
              sl_error_str(retv));
      exit(EXIT_FAILURE);
    }

    // запомнить время приема пакета
    daytime = get_daytime();

    if (verbose >= 2)
      printf("Receive UDP packet #%u from %s:%i size=%i\n",
             counter, sl_inet_ntoa(ip_addr), port, retv);

    // проверить число слов (должно быть не менее 3-х)
    if (retv < 3*sizeof(uint32_t))
    {
      if (verbose >= 2)
        printf("Size of UDP packet (%i bytes) is too short; continue\n", retv);
      continue;
    }

    // проверить первое слово (сигнатура)
    if (ntohl(recv_buf[0]) != PING_MAGIC)
    {
      if (verbose >= 1)
        printf("Bad signature %08X in packet #%u; continue\n",
               (unsigned) ntohl(recv_buf[0]), counter);
        continue;
    }

    // запомнить размер принятого ответа (ответить пакетом такого же размера)
    ans_size = retv;

    // проверить второе слово (счетчик пакетов)
    if (ntohl(recv_buf[1]) != counter)
    {
      if (verbose >= 1)
        printf("Some packet(s) may be lost (%i); correct counter\n",
               (int) (ntohl(recv_buf[1]) - counter));
      counter = ntohl(recv_buf[1]);
      lost_count++;
    }

    // время с момента приема предыдущего пакета
    if (recv_time != (uint32_t) -1)
      delta_time = (int32_t) daytime - recv_time;
    recv_time = daytime;

    // отправить ответный пакет
    send_buf[0] = htonl(PONG_MAGIC);
    send_buf[1] = htonl(counter);
    send_buf[2] = htonl(get_daytime());

    if (verbose >= 2)
      printf("Send UDP packet #%u to %s:%i size=%i\n",
             counter, sl_inet_ntoa(ip_addr), port, ans_size);

    if (stop_flag)
    { // Ctrl-C pressed
      fprintf(stderr, "\nCtrl-C pressed; exit\n");
      break;
    }

    // send datagram to peer via UDP to ip numeric
    retv = sl_udp_sendto(sock, ip_addr, port, send_buf, ans_size, 0);
    if (retv < 0)
    {
      fprintf(stderr, "Error in sl_udp_sendto(): '%s'; exit\n",
              sl_error_str(retv));
      exit(EXIT_FAILURE);
    }
    else if (retv != ans_size)
    {
      fprintf(stderr, "Error: sl_udp_sendto() send %i bytes instead %i; exit\n",
              retv, packet_size);
      exit(EXIT_FAILURE);
    }

    // сохранить статистику
    if (data_stdout)
    { // #counter #local_time #remote_time #delta_time
      printf(
        "%i %f %f %.6f\n",
        counter,                             // счетчик пакетов
        daytime_to_sec(daytime),             // время приема [s]
        daytime_to_sec(ntohl(recv_buf[2])),  // время отправки [s]
        deltatime_to_sec(delta_time) * 1e3); // интервал между пакетами [ms]
    }

    // проверить счетчик принятых пакетов
    if (packet_count && counter >= packet_count)
    {
      if (verbose >= 1)
        printf("Limit of packet counter; exit\n");
      break;
    }

    counter++;
  } // for(;;)
}
//-----------------------------------------------------------------------------
// обработчик сигнала таймера
static void timer_handler(int signo, siginfo_t *si, void *context)
{
  if (si->si_code == SI_TIMER)
  {
    int retv;
    timer_t *tidp = si->si_value.sival_ptr;

    retv = timer_getoverrun(*tidp);
    if (retv == -1)
      err_exit("timer_getoverrun() failed; exit");
    else
      overrun += retv;
  }
}
//-----------------------------------------------------------------------------
// обработчик сигнала SIGINT (Ctrl-C)
static void sigint_handler(int signo)
{
  stop_flag = 1;
}
//-----------------------------------------------------------------------------
// функция передатчика (UDP client)
static void sender()
{
  int retv;
  unsigned host_ip;   // IP адрес сервера
  int port;           // порт сервера

  struct timespec ts, tm, st;
  sigset_t mask;
  struct sigevent sigev;
  struct sigaction sa;
  struct itimerspec ival;
  timer_t timerid;

  if (verbose >= 1)
  {
    printf("PONG run in sender (UDP client) mode:\n");
    printf("  hostname      = %s\n", hostname);
    printf("  udp_port      = %i\n", udp_port);
    printf("  interval_ms   = %i\n", interval_ms);
    printf("  timeout_ms    = %i\n", timeout_ms);
    printf("  packet_size   = %i\n", packet_size);
    printf("  packet_count  = %i\n", packet_count);
    printf("  verbose level = %i\n", verbose);
    printf("  real time     = %s\n", realtime ? "yes" : "no");
  }

  // get remote host IP by name
  retv = sl_gethostbyname(hostname, &host_ip);
  if (retv < 0)
  {
    fprintf(stderr, "Error in sl_gethostbuname('%s'): '%s'; exit\n",
            hostname, sl_error_str(retv));
    exit(EXIT_FAILURE);
  }

  // make client UDP socket
  sock = sl_udp_make_client_socket();
  if (sock < 0)
  {
    fprintf(stderr, "Error in sl_udp_make_client_socket(): '%s'; exit\n",
            sl_error_str(sock));
    exit(EXIT_FAILURE);
  }

  // зарегистрировать обработчик сигнала таймера
  if (verbose >= 3)
    printf("Establishing handler for signal %d\n", SIG);
  memset((void*) &sa, 0, sizeof(sa));
  sa.sa_sigaction = timer_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  if (sigaction(SIG, &sa, NULL) == -1)
    err_exit("sigaction() failed; exit");

  // разблокировать сигнал (хотя он и так по умолчанию не блокирован)
  if (verbose >= 3)
    printf("Unblocking signal %d\n", SIG);
  sigemptyset(&mask);
  sigaddset(&mask, SIG);
  if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
    err_exit("sigprocmask() failed; exit");

  // создать таймер
  memset((void*) &sigev, 0, sizeof(sigev));
  sigev.sigev_notify = SIGEV_SIGNAL; // SIGEV_NONE SIGEV_SIGNAL SIGEV_THREAD...
  sigev.sigev_signo = SIG;
  sigev.sigev_value.sival_ptr = (void*) &timerid;
  //sigev.sigev_value.sival_int = 1; // use sival_ptr instead!
  //sigev.sigev_notify_function   = ...; // for SIGEV_THREAD
  //sigev.sigev_notify_attributes = ...; // for SIGEV_THREAD
  //sigev.sigev_notify_thread_id  = ...; // for SIGEV_THREAD_ID
  if (timer_create(CLOCKID, &sigev, &timerid) == -1)
    err_exit("timer_create() failed; exit");
  if (verbose >= 3)
    printf("Create timer ID = 0x%lx\n", (long) timerid);

  // запустить таймер
  ival.it_value    = double_to_ts(((double) interval_ms) * 1e-3);
  ival.it_interval = ival.it_value;
  if (timer_settime(timerid, 0, &ival, NULL) == -1)
    err_exit("timer_settime() failed; exit");

  // отправлять пакеты и ждать ответы
  for (;; counter++)
  {
    uint32_t send_time; // время отправки пакета
    uint32_t recv_time; // время приема ответного пакета
    unsigned ip_addr;   // IP address of echo sender

    if (stop_flag)
    { // Ctrl-C pressed
      fprintf(stderr, "\nCtrl-C pressed; exit\n");
      counter--;
      break;
    }

    // проверить счетчик отправленных пакетов
    if (packet_count && counter > packet_count)
    {
      if (verbose >= 1)
        printf("Limit of packet counter; exit\n");
      counter--;
      break;
    }

    // разблокировать сигнал таймера
    sigemptyset(&mask);
    sigaddset(&mask, SIG);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
      err_exit("sigprocmask() failed; exit");

    pause(); // заснуть до прихода сигнала от таймера

    // заблокировать сигнал, чтобы он не прерывал select()
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
      err_exit("sigprocmask() failed; exit");

    if (verbose >= 2)
      printf("Send UDP packet to %s:%i size=%i\n",
             hostname, udp_port, packet_size);

    send_buf[0] = htonl(PING_MAGIC);
    send_buf[1] = htonl(counter);
    send_buf[2] = htonl(send_time = get_daytime());

    if (stop_flag)
    { // Ctrl-C pressed
      fprintf(stderr, "\nCtrl-C pressed; exit\n");
      counter--;
      break;
    }

    // send datagram to peer via UDP to ip numeric
    retv = sl_udp_sendto(sock, host_ip, udp_port,
                         send_buf, packet_size, 0);
    if (retv < 0)
    {
      fprintf(stderr, "Error in sl_udp_sendto(): '%s'; exit\n",
              sl_error_str(retv));
      exit(EXIT_FAILURE);
    }
    else if (retv != packet_size)
    {
      fprintf(stderr, "Error: sl_udp_sendto() send %i bytes instead %i; exit\n",
              retv, packet_size);
      exit(EXIT_FAILURE);
    }

try_again: // FIXME

    if (stop_flag)
    { // Ctrl-C pressed
      fprintf(stderr, "\nCtrl-C pressed; exit\n");
      break;
    }

    // ожидать ответного пакета
    // read datagram from UDP socket (timeout)
    retv = sl_udp_read_to(sock, recv_buf, sizeof(recv_buf),
                          &ip_addr, &port, timeout_ms);

    // запомнить время приема пакета
    recv_time = get_daytime();

    if (stop_flag)
    { // Ctrl-C pressed
      fprintf(stderr, "\nCtrl-C pressed; exit\n");
      break;
    }

    if (retv == SL_TIMEOUT)
    {
      if (verbose >= 1)
        printf("Packet #%i lost by timeout; send next packet\n", counter);
      lost_count++;

      // сохранить в статистике факт пропуска пакета (нулевая задержка)
      if (data_stdout)
      { // #counter #local_time #remote_time #delta_time
        printf(
          "%i %f %f %.6f\n",
          counter,                   // счетчик пакетов
          daytime_to_sec(recv_time), // время получения s]
          daytime_to_sec(send_time), // время отправки [s]
          0.);                       // туда-обратно [ms]
      }
      continue;
    }

    if (retv < 0)
    {
      fprintf(stderr, "Error in sl_udp_read_to(): '%s'; exit\n",
              sl_error_str(retv));
      exit(EXIT_FAILURE);
    }

    if (verbose >= 2)
      printf("Receive UDP packet from %s:%i size=%i time=%.3g ms\n",
             sl_inet_ntoa(ip_addr), port, retv,
             deltatime_to_sec(recv_time - send_time) * 1e3);

    // проверить число слов (должно быть не менее 3-х)
    if (retv < 3*sizeof(uint32_t))
    {
      if (verbose >= 1 && retv != 0)
        printf("Size of UDP packet (%i bytes) is too short; continue\n", retv);
      lost_count++;
      continue;
    }

    // проверить первое слово (сигнатура)
    if (ntohl(recv_buf[0]) != PONG_MAGIC)
    {
      if (verbose >= 1)
        printf("Bad signature %08X; continue\n",
               (unsigned) ntohl(recv_buf[0]));
        goto try_again;
    }

    // проверить второе слово (счетчик пакетов)
    if (ntohl(recv_buf[1]) != counter)
    {
      int old = counter - ntohl(recv_buf[1]);
      if (old > 0 && old <= 3) // FIXME
      {
        if (verbose >= 1)
          printf("Receive old packet %u instead %u; continue\n",
                (unsigned) ntohl(recv_buf[1]), (unsigned) counter);
        goto try_again;
      }
      else
      {
        if (verbose >= 1)
          printf("Answer packet counter incorrect %u instead %u\n",
                (unsigned) ntohl(recv_buf[1]), (unsigned) counter);
        lost_count++;
      }
    }

    // вывод "аля ping"
    if (verbose == 1)
      printf(
        "#%i: %i bytes from %s:%i: time=%g ms\n",
        //counter, retv, sl_inet_ntoa(ip_addr), port,
        counter, retv, hostname, udp_port,
        deltatime_to_sec(recv_time - send_time) * 1e3);

    // сохранить статистику
    if (data_stdout)
    { // #counter #local_time #remote_time #delta_time
      printf(
        "%i %f %f %.6f\n",
        counter,                                        // счетчик пакетов
        daytime_to_sec(recv_time),                      // время получения [s]
        daytime_to_sec(ntohl(recv_buf[2])),             // время отправки [s]
        deltatime_to_sec(recv_time - send_time) * 1e3); // туда-обратно [ms]
    }
  } // for(;; counter++)
}
//-----------------------------------------------------------------------------
int main(int argc, const char *argv[])
{
  uint32_t daytime = get_daytime();

  sigset_t mask;
  struct sigevent sigev;
  struct sigaction sa;
  FILE *fo = stdout; // statstics output (stdout/stderr)

  // init socklib
  sl_init();

  // разобрать опции командной строки
  parse_options(argc, argv);

  // установить "real-time" приоритет
  if (realtime)
    set_realtime_priority();

  // зарегистрировать обработчик сигнала SIGINT
  if (verbose >= 3)
    printf("Establishing handler for signal %d\n", SIGINT);
#if 0
  memset((void*) &sa, 0, sizeof(sa));
  sa.sa_handler = sigint_handler;
  sigemptyset(&sa.sa_mask);
  //sa.sa_flags = 0;
  if (sigaction(SIGINT, &sa, NULL) == -1)
    err_exit("sigaction() failed; exit");
#else
  signal(SIGINT, sigint_handler); // old school ;-)
#endif

  // вывести на консоль начальное время
  if (verbose >= 2)
  {
    printf("Local day time is ");
    print_daytime(daytime);
    printf("\n");
  }

  if (data_stdout)
    fo = stderr;

  if (echo_mode)
  {
    receiver();
    fprintf(fo, "--- UDP pong server %s:%i statisticts ---\n",
            listen_ip, udp_port);
    fprintf(fo,
            "%u packet(s) received last session; "
            "%u packet(s) may be lost (%g%%)\n",
            counter, lost_count,
            ((double) lost_count) / ((double) counter) * 100.);
  }
  else
  {
    sender();
    fprintf(fo, "--- UDP pong client statistics to %s:%i ---\n",
            hostname, udp_port);
    fprintf(fo,
            "%u packet(s) send; %u echo packet(s) lost (%g%%)\n",
            counter, lost_count,
            ((double) lost_count) / ((double) counter) * 100.);
  }

  // term socklib
  sl_term();

  return EXIT_SUCCESS;
}
//-----------------------------------------------------------------------------

/*** end of "pong.c" ***/
