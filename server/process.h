#ifndef __SSSD_PROCESS_H__
#define __SSSD_PROCESS_H__

int process_new_task(struct event_context *ev,
			    const char *service_name,
			    void (*new_task)(struct event_context *, void *),
			    void *private,
			    pid_t *rpid);
void process_set_title(struct event_context *ev, const char *title);
void process_terminate(struct event_context *ev, const char *reason);

#endif /* __SSSD_PROCESS_H__ */

