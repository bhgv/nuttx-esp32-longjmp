
#include <stdio.h>
#include <stdint.h>

#include <string.h>

#include "drv_cmd.h"


#if 0
#define TRC(...) printf(__VA_ARGS__)
#else
#define TRC(...) 
#endif

#if 0
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...) 
#endif


parser_cb parse_drv_cmd(FAR const parser_cmd* drv_cmds, FAR const char *buffer, size_t buflen, unsigned* flags_o, int* idat_o)
{
  int i, idat=-1, ipar=-1;
  char rd_cmd[CMD_LEN_MAX+1];

  if(idat_o) *idat_o = -1;
  if(flags_o) *flags_o = -1;

  TRC("%s:%d\n", __func__, __LINE__);
  for(i = 0; i < buflen && i < CMD_LEN_MAX && buffer[i] != ':' && buffer[i] != ','; i++){
    DBG("%c", buffer[i]);
    rd_cmd[i] = buffer[i];
    }
  DBG("%c\n", buffer[i]);
  rd_cmd[i] = '\0';

  TRC("%s:%d i=%d buflen=%d\n", __func__, __LINE__, i, buflen);
  if(i < buflen){
    if(buffer[i] == ',')
      ipar = i+1;
    else
      ipar = -1;

    TRC("%s:%d\n", __func__, __LINE__);
    for(idat = 0; idat < buflen && buffer[idat] != ':'; idat++);
    TRC("%s:%d\n", __func__, __LINE__);
    if(idat < buflen){
      idat++;
      }
    }else{
      return NULL;
    }

  TRC("%s:%d\n", __func__, __LINE__);
  for(i = 0; drv_cmds[i].name != NULL; i++){
    TRC("%s:%d nm=%s\n", __func__, __LINE__, drv_cmds[i].name);
    if(!strcmp(drv_cmds[i].name, rd_cmd)){
      if(drv_cmds[i].cb != NULL){
        if(idat_o) *idat_o = idat;
        if(flags_o) *flags_o = drv_cmds[i].flags;
        TRC("%s:%d cb=%X\n", __func__, __LINE__, drv_cmds[i].cb);
        return drv_cmds[i].cb;
        }
      }
    }
  TRC("%s:%d\n", __func__, __LINE__);
  return NULL;
}


void help_drv_cmds(FAR const parser_cmd* drv_cmds)
{
  int i;

  printf("\nHelp:\n");
  for(i = 0; drv_cmds[i].name != NULL; i++){
    if(drv_cmds[i].cb != NULL)
      printf("%s) %s:%s\n", (drv_cmds[i].flags == 0 ? "Rd" : "Wr"), drv_cmds[i].name, (drv_cmds[i].flags == 0 ? "" : "...data..."));
    }
}





void dev_databuf_init(dev_databuf* db, char* init_data, int len){
  if(db == NULL || len <= 0)
      return;

  TRC("%s:%d\n", __func__, __LINE__);
   if(db->buf != NULL)
    return;

   TRC("%s:%d\n", __func__, __LINE__);
   db->i = 0;

   TRC("%s:%d\n", __func__, __LINE__);
  db->buf = malloc(len);
  if(db->buf == NULL)
    return;

  TRC("%s:%d buf=%X, dat=%X, len=%d\n", __func__, __LINE__, db->buf, init_data, len);
  if(init_data != NULL){
    for(int i = 0; i < len; i++){
      TRC("%s:%d i=%d\n", __func__, __LINE__, i);
      db->buf[i] = init_data[i];
      }
    TRC("%s:%d\n", __func__, __LINE__);
    db->len = len;
    }
  else{
    TRC("%s:%d\n", __func__, __LINE__);
    db->len = 0;
    }
  
  TRC("%s:%d\n", __func__, __LINE__);
}


void dev_databuf_deinit(dev_databuf* db){
  if(db == NULL)
      return;

  if(db->buf)
    free(db->buf);
  db->buf = NULL;
  db->len = 0;
  db->i = 0;
}


int dev_databuf_out(dev_databuf* db, char* buf_o, int buf_len){
  int i;

  if(db == NULL || buf_o == NULL || buf_len <= 0)
      return 0;

  TRC("%s:%d\n", __func__, __LINE__);
  if(db->buf == NULL || db->len == 0 || db->i >= db->len)
    return 0;

  TRC("%s:%d\n", __func__, __LINE__);
  for(i = 0; i < buf_len && db->i < db->len; i++, db->i++){
    buf_o[i] = db->buf[db->i];
    }
  
  TRC("%s:%d\n", __func__, __LINE__);
  return i;
}


