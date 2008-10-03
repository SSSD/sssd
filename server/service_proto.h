#ifndef __SSSD_SERVICE_PROTO_H__
#define __SSSD_SERVICE_PROTO_H__

/* The following definitions come from service.c  */

NTSTATUS register_server_service(const char *name,
				 void (*task_init)(struct task_server *));
NTSTATUS server_service_startup(struct event_context *event_ctx,
				struct loadparm_context *lp_ctx,
				const char *model, const char **server_services);

/* The following definitions come from service_task.c  */

void task_server_terminate(struct task_server *task, const char *reason);
NTSTATUS task_server_startup(struct event_context *event_ctx,
			     struct loadparm_context *lp_ctx,
			     const char *service_name,
			     const struct model_ops *model_ops,
			     void (*task_init)(struct task_server *));
void task_server_set_title(struct task_server *task, const char *title);

#endif /* __SSSD_SERVICE_PROTO_H__ */

