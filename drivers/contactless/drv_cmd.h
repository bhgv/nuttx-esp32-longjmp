#ifndef _DRV_CMD_H_
#define _DRV_CMD_H_


#define CMD_LEN_MAX  32


typedef int (*parser_cb)(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]);


typedef struct {
  char* name;
  int  def_val;
} parser_param;


typedef struct {
  char* name;

  parser_cb cb;

  unsigned flags;
  
  int par_cnt;
  const parser_param* par_lst;
} parser_cmd;


parser_cb parse_drv_cmd(FAR const parser_cmd* drv_cmds, FAR const char *buffer, size_t buflen, unsigned* flags_o, int* idat_o);

void help_drv_cmds(FAR const parser_cmd* drv_cmds);




typedef struct {
  char* buf;
  int len;
  int i;
} dev_databuf;


void dev_databuf_init(dev_databuf* db, char* init_data, int len);
void dev_databuf_deinit(dev_databuf* db);

int dev_databuf_out(dev_databuf* db, char* buf_o, int buf_len);


#endif /* _DRV_CMD_H_ */

