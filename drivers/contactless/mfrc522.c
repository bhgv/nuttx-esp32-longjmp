/****************************************************************************
 * drivers/contactless/mfrc522.c
 *
 *   Copyright(C) 2016 Uniquix Ltda. All rights reserved.
 *   Author: Alan Carvalho de Assis <acassis@gmail.com>
 *
 * This driver is based on Arduino library for MFRC522 from Miguel
 * Balboa released into the public domain:
 * https://github.com/miguelbalboa/rfid/
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <ctype.h>

#include <nuttx/kmalloc.h>
#include <nuttx/signal.h>
#include <nuttx/contactless/mfrc522.h>

#include "mfrc522.h"

#if 0
#define TRC(...) printf(__VA_ARGS__)
#else
#define TRC(...) 
#endif

#if 1
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...) 
#endif


/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#ifdef CONFIG_CL_MFRC522_DEBUG
#  define mfrc522err    _err
#  define mfrc522info   _info
#else
#  ifdef CONFIG_CPP_HAVE_VARARGS
#    define mfrc522err(x...)
#    define mfrc522info(x...)
#  else
#    define mfrc522err  (void)
#    define mfrc522info (void)
#  endif
#endif

#ifdef CONFIG_CL_MFRC522_DEBUG_TX
#  define tracetx errdumpbuffer
#else
#  define tracetx(x...)
#endif

#ifdef CONFIG_CL_MFRC522_DEBUG_RX
#  define tracerx errdumpbuffer
#else
#  define tracerx(x...)
#endif

#define FRAME_SIZE(f) (sizeof(struct mfrc522_frame) + f->len + 2)
#define FRAME_POSTAMBLE(f) (f->data[f->len + 1])

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static inline void mfrc522_configspi(FAR struct spi_dev_s *spi);
static void mfrc522_lock(FAR struct spi_dev_s *spi);
static void mfrc522_unlock(FAR struct spi_dev_s *spi);

/* Character driver methods */

static int mfrc522_open(FAR struct file *filep);
static int mfrc522_close(FAR struct file *filep);
static ssize_t mfrc522_read(FAR struct file *, FAR char *, size_t);
static ssize_t mfrc522_write(FAR struct file *filep, FAR const char *buffer,
                             size_t buflen);
static int mfrc522_ioctl(FAR struct file *filep, int cmd,
                         unsigned long arg);

uint8_t mfrc522_readu8(FAR struct mfrc522_dev_s *dev, uint8_t regaddr);
void mfrc522_writeu8(FAR struct mfrc522_dev_s *dev, uint8_t regaddr,
                     FAR uint8_t regval);
void mfrc522_writeblk(FAR struct mfrc522_dev_s *dev, uint8_t regaddr,
                      uint8_t *regval, int length);
void mfrc522_readblk(FAR struct mfrc522_dev_s *dev, uint8_t regaddr,
                     FAR uint8_t *regval, int length, uint8_t rxalign);

void mfrc522_softreset(FAR struct mfrc522_dev_s *dev);

int mfrc522_picc_select(FAR struct mfrc522_dev_s *dev,
                        FAR struct picc_uid_s *uid, uint8_t validbits);



int MIFARE_TwoStepHelper(FAR struct mfrc522_dev_s *dev,
                          uint8_t command, ///< The command to use
                          uint8_t blockAddr, ///< The block (0-0xff) number.
                          int32_t data    ///< The data to transfer in step 2
);

int PCD_MIFARE_Transceive(FAR struct mfrc522_dev_s *dev,
                        uint8_t *sendData,   ///< Pointer to the data to transfer to the FIFO. Do NOT include the CRC_A.
                        uint8_t sendLen,   ///< Number of bytes in sendData.
                        bool acceptTimeout  ///< True => A timeout is also success
);

void PICC_DumpDetailsToSerial(FAR struct mfrc522_dev_s *dev,
                          struct picc_uid_s *uid ///< Pointer to Uid struct returned from a successful PICC_Select().
);

void PICC_DumpMifareClassicToSerial(FAR struct mfrc522_dev_s *dev,
                               struct picc_uid_s *uid,  ///< Pointer to Uid struct returned from a successful PICC_Select().
                               uint8_t piccType,    ///< One of the PICC_Type enums.
                               MIFARE_Key *key   ///< Key A used for all sectors.
);

void PICC_DumpMifareUltralightToSerial(FAR struct mfrc522_dev_s *dev);

void PICC_DumpMifareClassicSectorToSerial(FAR struct mfrc522_dev_s *dev,
                                    struct picc_uid_s *uid,      ///< Pointer to Uid struct returned from a successful PICC_Select().
                                    MIFARE_Key *key,  ///< Key A for the sector.
                                    uint8_t sector     ///< The sector to dump, 0..39.
);


struct picc_uid_s uid;


#define NEW_UID {0xDE, 0xAD, 0xBE, 0xEF}



/* IRQ Handling TODO:
static int mfrc522_irqhandler(FAR int irq, FAR void *context, FAR void* dev);
static inline int mfrc522_attachirq(FAR struct mfrc522_dev_s *dev, xcpt_t isr);
*/

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const struct file_operations g_mfrc522fops =
{
  mfrc522_open,
  mfrc522_close,
  mfrc522_read,
  mfrc522_write,
  0,
  mfrc522_ioctl
#ifndef CONFIG_DISABLE_POLL
    , 0
#endif
#ifndef CONFIG_DISABLE_PSEUDOFS_OPERATIONS
    , 0
#endif
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void mfrc522_lock(FAR struct spi_dev_s *spi)
{
  (void)SPI_LOCK(spi, true);

  SPI_SETMODE(spi, SPIDEV_MODE0);
  SPI_SETBITS(spi, 8);
  (void)SPI_HWFEATURES(spi, 0);
  (void)SPI_SETFREQUENCY(spi, CONFIG_MFRC522_SPI_FREQ);
}

static void mfrc522_unlock(FAR struct spi_dev_s *spi)
{
  (void)SPI_LOCK(spi, false);
}

static inline void mfrc522_configspi(FAR struct spi_dev_s *spi)
{
  /* Configure SPI for the MFRC522 module. */

  SPI_SETMODE(spi, SPIDEV_MODE0);
  SPI_SETBITS(spi, 8);
  (void)SPI_HWFEATURES(spi, 0);
  (void)SPI_SETFREQUENCY(spi, CONFIG_MFRC522_SPI_FREQ);
}

static inline void mfrc522_select(struct mfrc522_dev_s *dev)
{
  SPI_SELECT(dev->spi, SPIDEV_CONTACTLESS(0), true);
}

static inline void mfrc522_deselect(struct mfrc522_dev_s *dev)
{
  SPI_SELECT(dev->spi, SPIDEV_CONTACTLESS(0), false);
}

/****************************************************************************
 * Name: mfrc522_readu8
 *
 * Description:
 *   Read a byte from a register address.
 *
 * Input Parameters:
 *
 * Returned Value: the read byte from the register
 *
 ****************************************************************************/

uint8_t mfrc522_readu8(FAR struct mfrc522_dev_s *dev, uint8_t regaddr)
{
  uint8_t regval;
  uint8_t address = (0x80 | (regaddr & 0x7E));

  mfrc522_lock(dev->spi);
  mfrc522_select(dev);
  SPI_SEND(dev->spi, address);
  regval = SPI_SEND(dev->spi, 0);
  mfrc522_deselect(dev);
  mfrc522_unlock(dev->spi);

  tracerx("read", regval, 1);
  return regval;
}

/****************************************************************************
 * Name: mfrc522_write8
 *
 * Description:
 *   Write a byte to a register address.
 *
 * Input Parameters:
 *
 * Returned Value:
 *
 ****************************************************************************/

void mfrc522_writeu8(FAR struct mfrc522_dev_s *dev, uint8_t regaddr,
                     FAR uint8_t regval)
{
  mfrc522_lock(dev->spi);
  mfrc522_select(dev);
  SPI_SEND(dev->spi, regaddr & 0x7E);
  SPI_SEND(dev->spi, regval);
  mfrc522_deselect(dev);
  mfrc522_unlock(dev->spi);

  tracerx("write", &regval, 1);
}

/****************************************************************************
 * Name: mfrc522_readblk
 *
 * Description:
 *   Read a block of bytes from a register address. Align the bit positions of
 * regval[0] from rxalign..7.
 *
 * Input Parameters:
 *
 * Returned Value: none
 *
 ****************************************************************************/

void mfrc522_readblk(FAR struct mfrc522_dev_s *dev, uint8_t regaddr,
                     FAR uint8_t *regval, int length, uint8_t rxalign)
{
  uint8_t i = 0;
  uint8_t address = (0x80 | (regaddr & 0x7E));

  mfrc522_lock(dev->spi);
  mfrc522_select(dev);

  /* Inform the MFRC522 the address we want to read */

  SPI_SEND(dev->spi, address);

  while (i < length)
    {
      if (i == 0 && rxalign)
        {
          uint8_t mask = 0;
          uint8_t value;
          uint8_t j;

          for (j = rxalign; j <= 7; j++)
            {
              mask |= (1 << j);
            }

          /* Read the first byte */

          value = SPI_SEND(dev->spi, address);

          /* Apply mask to current regval[0] with the read value */

          regval[0] = (regval[0] & ~mask) | (value & mask);
        }
      else
        {
          /* Read the remaining bytes */

          regval[i] = SPI_SEND(dev->spi, address);
        }
      i++;
    }

  /* Read the last byte. Send 0 to stop reading (it maybe wrong, 1 byte out) */

  regval[i] = SPI_SEND(dev->spi, 0);

  mfrc522_deselect(dev);
  mfrc522_unlock(dev->spi);

  tracerx("readblk", regval, size);
}

/****************************************************************************
 * Name: mfrc522_writeblk
 *
 * Description:
 *   Write a block of bytes to a register address.
 *
 * Input Parameters:
 *
 * Returned Value: none
 *
 ****************************************************************************/

void mfrc522_writeblk(FAR struct mfrc522_dev_s *dev, uint8_t regaddr,
                      uint8_t *regval, int length)
{
  uint8_t address = (regaddr & 0x7E);

  mfrc522_lock(dev->spi);
  mfrc522_select(dev);

  /* Inform the MFRC522 the address we want write to */

  SPI_SEND(dev->spi, address);

  /* Send the block of bytes */

  SPI_SNDBLOCK(dev->spi, regval, length);

  mfrc522_deselect(dev);
  mfrc522_unlock(dev->spi);

  tracerx("writeblk", regval, size);
}


/**
 * Sets the bits given in mask in register reg.
 */
void PCD_SetRegisterBitMask(FAR struct mfrc522_dev_s *dev, 
                    uint8_t reg,     ///< The register to update. One of the PCD_Register enums.
                    uint8_t mask     ///< The bits to set.
                  ) { 
  uint8_t tmp;
  tmp = mfrc522_readu8(dev, reg);
  mfrc522_writeu8(dev, reg, tmp | mask);     // set bit mask
} // End PCD_SetRegisterBitMask()

/**
 * Clears the bits given in mask from register reg.
 */
void PCD_ClearRegisterBitMask(FAR struct mfrc522_dev_s *dev,
                    uint8_t reg,     ///< The register to update. One of the PCD_Register enums.
                    uint8_t mask     ///< The bits to clear.
                    ) {
  uint8_t tmp;
  tmp = mfrc522_readu8(dev, reg);
  mfrc522_writeu8(dev, reg, tmp & (~mask));    // clear bit mask
} // End PCD_ClearRegisterBitMask()




/****************************************************************************
 * Name: mfrc522_calc_crc
 *
 * Description:
 *   Use the CRC coprocessor in the MFRC522 to calculate a CRC_A.
 *
 * Input Parameters:
 *
 * Returned Value: OK or -ETIMEDOUT
 *
 ****************************************************************************/

int mfrc522_calc_crc(FAR struct mfrc522_dev_s *dev, uint8_t *buffer,
                     int length, uint8_t *result)
{
  struct timespec tstart;
  struct timespec tend;

  /* Stop any command in execution */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, MFRC522_IDLE_CMD);

  /* Clear the CRCIRq interrupt request bit */

  mfrc522_writeu8(dev, MFRC522_DIV_IRQ_REG, MFRC522_CRC_IRQ);

  /* Flush all bytes in the FIFO */

  mfrc522_writeu8(dev, MFRC522_FIFO_LEVEL_REG, MFRC522_FLUSH_BUFFER);

  /* Write data to the FIFO */

  mfrc522_writeblk(dev, MFRC522_FIFO_DATA_REG, buffer, length);

  /* Start the calculation */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, MFRC522_CALC_CRC_CMD);

  /* Wait for CRC completion or 200ms time-out */

  clock_gettime(CLOCK_REALTIME, &tstart);
  tstart.tv_nsec += 200000;
  if (tstart.tv_nsec >= 1000 * 1000 * 1000)
    {
      tstart.tv_sec++;
      tstart.tv_nsec -= 1000 * 1000 * 1000;
    }

  while(1)
    {
      uint8_t irqreg;

      irqreg = mfrc522_readu8(dev, MFRC522_DIV_IRQ_REG);
      if ( irqreg & MFRC522_CRC_IRQ)
        {
          break;
        }

      /* Get time now */

      clock_gettime(CLOCK_REALTIME, &tend);

      if ((tend.tv_sec > tstart.tv_sec) && (tend.tv_nsec > tstart.tv_nsec))
        {
          return -ETIMEDOUT;
        }
    }

  /* Stop calculating CRC for new content of FIFO */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, MFRC522_IDLE_CMD);

  result[0] = mfrc522_readu8(dev, MFRC522_CRC_RESULT_REGL);
  result[1] = mfrc522_readu8(dev, MFRC522_CRC_RESULT_REGH);

  return OK;
}

/****************************************************************************
 * Name: mfrc522_comm_picc
 *
 * Description:
 *   Transfers data to the MFRC522 FIFO, executes a command, waits for
 * completion and transfers data back from the FIFO.
 * CRC validation can only be done if back_data and back_len are specified.
 *
 * Input Parameters:
 *
 * Returned Value: OK or -ETIMEDOUT
 *
 ****************************************************************************/

int mfrc522_comm_picc(FAR struct mfrc522_dev_s *dev, uint8_t command,
                      uint8_t waitirq, uint8_t *send_data, uint8_t send_len,
                      uint8_t *back_data, uint8_t *back_len,
                      uint8_t *validbits, uint8_t rxalign, bool checkcrc)
{
  int ret;
  uint8_t errors;
  uint8_t vbits;
  uint8_t value;
  struct timespec tstart;
  struct timespec tend;

  /* Prepare values for BitFramingReg */

  uint8_t txlastbits = validbits ? *validbits : 0;
  uint8_t bitframing = (rxalign << 4) + txlastbits;

TRC("%s:%d\n", __func__, __LINE__);
  /* Stop any active command */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, MFRC522_IDLE_CMD);

  /* Clear all seven interrupt request bits */

TRC("%s:%d\n", __func__, __LINE__);
  value = mfrc522_readu8(dev, MFRC522_COM_IRQ_REG);
  mfrc522_writeu8(dev, MFRC522_COM_IRQ_REG, value | MFRC522_COM_IRQ_MASK);

TRC("%s:%d\n", __func__, __LINE__);
  /* Flush all bytes in the FIFO */

  mfrc522_writeu8(dev, MFRC522_FIFO_LEVEL_REG, MFRC522_FLUSH_BUFFER);

TRC("%s:%d\n", __func__, __LINE__);
  /* Write data to FIFO */

  mfrc522_writeblk(dev, MFRC522_FIFO_DATA_REG, send_data, send_len);

TRC("%s:%d\n", __func__, __LINE__);
  /* Bit adjustments */

  mfrc522_writeu8(dev, MFRC522_BIT_FRAMING_REG, bitframing);

TRC("%s:%d\n", __func__, __LINE__);
  /* Execute command */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, command);

  /* We setup the TAuto flag in the mfrc522_init() then we could use the
   * internal MFC522 Timer to detect timeout, but because there could be some
   * hardware fault, let us to use a NuttX timeout as well.
   */

  clock_gettime(CLOCK_REALTIME, &tstart);
  tstart.tv_nsec += 200000;
  if (tstart.tv_nsec >= 1000 * 1000 * 1000)
    {
      tstart.tv_sec++;
      tstart.tv_nsec -= 1000 * 1000 * 1000;
    }

  /* If it is a Transceive command, then start transmittion */

  if (command == MFRC522_TRANSCV_CMD)
    {
TRC("%s:%d\n", __func__, __LINE__);
      value = mfrc522_readu8(dev, MFRC522_BIT_FRAMING_REG);
      mfrc522_writeu8(dev, MFRC522_BIT_FRAMING_REG, value | MFRC522_START_SEND);
    }

  /* Wait for the command to complete */

  while (1)
    {
      uint8_t irqsreg;

TRC("%s:%d\n", __func__, __LINE__);
      irqsreg = mfrc522_readu8(dev, MFRC522_COM_IRQ_REG);

      /* If at least an of selected IRQ happened */

      if (irqsreg & waitirq)
        {
TRC("%s:%d\n", __func__, __LINE__);
          break;
        }

      /* Timer expired */

      if (irqsreg & MFRC522_TIMER_IRQ)
        {
TRC("%s:%d\n", __func__, __LINE__);
          return -ETIMEDOUT;
        }

      /* Get time now */

      clock_gettime(CLOCK_REALTIME, &tend);

      if ((tend.tv_sec > tstart.tv_sec) && (tend.tv_nsec > tstart.tv_nsec))
        {
TRC("%s:%d\n", __func__, __LINE__);
          return -ETIMEDOUT;
        }
    }

  /* Read error register to verify if there are any issue */

TRC("%s:%d\n", __func__, __LINE__);
  errors = mfrc522_readu8(dev, MFRC522_ERROR_REG);

  /* Check for Protocol error */

  if (errors & (MFRC522_PROTO_ERR))
    {
TRC("%s:%d\n", __func__, __LINE__);
      return -EPROTO;
    }

  /* Check for Parity and Buffer Overflow errors */

  if (errors & (MFRC522_PARITY_ERR | MFRC522_BUF_OVFL_ERR))
    {
TRC("%s:%d\n", __func__, __LINE__);
      return -EIO;
    }

  /* Check collision error */

  if (errors & MFRC522_COLL_ERR)
    {
TRC("%s:%d\n", __func__, __LINE__);
      return -EBUSY;            /* should it be EAGAIN ? */
    }

  /* If the caller wants data back, get it from the MFRC522 */

  if (back_data && back_len)
    {
      uint8_t nbytes;

      /* Number of bytes in the FIFO */

TRC("%s:%d\n", __func__, __LINE__);
      nbytes = mfrc522_readu8(dev, MFRC522_FIFO_LEVEL_REG);

      /* Returned more bytes than the expected */

      if (nbytes > *back_len)
        {
TRC("%s:%d\n", __func__, __LINE__);
          return -ENOMEM;
        }

      *back_len = nbytes;

      /* Read the data from FIFO */

TRC("%s:%d\n", __func__, __LINE__);
      mfrc522_readblk(dev, MFRC522_FIFO_DATA_REG, back_data, nbytes, rxalign);

      /* RxLastBits[2:0] indicates the number of valid bits received */

TRC("%s:%d\n", __func__, __LINE__);
      vbits = mfrc522_readu8(dev, MFRC522_CONTROL_REG)
              & MFRC522_RX_LAST_BITS_MASK;

      if (validbits)
        {
          *validbits = vbits;
        }
    }

  /* Perform CRC_A validation if requested */

  if (back_data && back_len && checkcrc)
    {
      uint8_t ctrlbuf[2];

      /* In this case a MIFARE Classic NAK is not OK */

      if (*back_len == 1 && vbits == 4)
        {
TRC("%s:%d\n", __func__, __LINE__);
          return -EACCES;
        }

      /* We need the CRC_A value or all 8 bits of the last byte */

      if (*back_len < 2 || vbits != 0)
        {
TRC("%s:%d\n", __func__, __LINE__);
          return -EPERM;
        }

      /* Verify CRC_A */

TRC("%s:%d\n", __func__, __LINE__);
      ret = mfrc522_calc_crc(dev, &back_data[0], *back_len - 2, &ctrlbuf[0]);
      if (ret != OK)
        {
TRC("%s:%d ret=%d\n", __func__, __LINE__, ret);
          return ret;
        }

      if ((back_data[*back_len - 2] != ctrlbuf[0]) ||
          (back_data[*back_len - 1] != ctrlbuf[1]))
        {
TRC("%s:%d\n", __func__, __LINE__);
          return -EFAULT;
        }
    }

  return OK;
}

/****************************************************************************
 * Name: mfrc522_transcv_data
 *
 * Description:
 *   Executes the Transceive command
 *
 * Input Parameters:
 *
 * Returned Value: OK or -ETIMEDOUT
 *
 ****************************************************************************/

int mfrc522_transcv_data(FAR struct mfrc522_dev_s *dev, uint8_t *senddata,
                         uint8_t sendlen, uint8_t *backdata, uint8_t *backlen,
                         uint8_t *validbits, uint8_t rxalign, bool check_crc)
{
  uint8_t waitirq = MFRC522_RX_IRQ | MFRC522_IDLE_IRQ;

  return mfrc522_comm_picc(dev, MFRC522_TRANSCV_CMD, waitirq, senddata,
                           sendlen, backdata, backlen, validbits, rxalign,
                           check_crc);
}

/****************************************************************************
 * Name: mfrc522_picc_reqa_wupa
 *
 * Description:
 *   Transmits REQA or WUPA commands
 *
 * Input Parameters:
 *
 * Returned Value: OK or -ETIMEDOUT
 *
 ****************************************************************************/

int mfrc522_picc_reqa_wupa(FAR struct mfrc522_dev_s *dev, uint8_t command,
                           uint8_t *buffer, uint8_t length)
{
  uint8_t validbits;
  uint8_t value;
  int status;

  if (!buffer || length < 2)
    {
      return -EINVAL;
    }

  /* Force clear of received bits if a collision is detected */

  value = mfrc522_readu8(dev, MFRC522_COLL_REG);
  mfrc522_writeu8(dev, MFRC522_COLL_REG, value & MFRC522_VALUES_AFTER_COLL);

  validbits = 7;
  status = mfrc522_transcv_data(dev, &command, 1, buffer, &length, &validbits,
                                0, false);

  /* For REQA and WUPA we need to transmit only 7 bits */

  if (status != OK)
    {
      return status;
    }

  /* ATQA must be exactly 16 bits */

  if (length != 2 || validbits != 0)
    {
      return -EAGAIN;
    }

  mfrc522info("buffer[0]=0x%02X | buffer[1]=0x%02X\n", buffer[0], buffer[1]);
  return OK;
}

/****************************************************************************
 * Name: mfrc522_picc_request_a
 *
 * Description:
 *   Transmits a REQuest command, Type A. Invites PICCs in state IDLE to go to
 * READY and prepare for anticollision or selection.
 *
 * Input Parameters:
 *
 * Returned Value: OK or -ETIMEDOUT
 *
 ****************************************************************************/

int mfrc522_picc_request_a(FAR struct mfrc522_dev_s *dev, uint8_t *buffer,
                           uint8_t length)
{
  return mfrc522_picc_reqa_wupa(dev, PICC_CMD_REQA, buffer, length);
}

/**
 * Transmits a Wake-UP command, Type A. Invites PICCs in state IDLE and HALT to go to READY(*) and prepare for anticollision or selection. 7 bit frame.
 * Beware: When two PICCs are in the field at the same time I often get STATUS_TIMEOUT - probably due do bad antenna design.
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int mfrc522_picc_wakeup_a(FAR struct mfrc522_dev_s *dev, 
                       uint8_t *buffer,  ///< The buffer to store the ATQA (Answer to request) in
                       uint8_t *length  ///< Buffer size, at least two bytes. Also number of bytes returned if STATUS_OK.
) {
  return mfrc522_picc_reqa_wupa(dev, PICC_CMD_WUPA, buffer, *length);
} // End mfrc522_picc_wakeup_a()


/****************************************************************************
 * Name: mfrc522_picc_detect
 *
 * Description:
 *   Detects if a Contactless Card is near
 *
 * Input Parameters:
 *
 * Returned Value: OK or -ETIMEDOUT
 *
 ****************************************************************************/

int mfrc522_picc_detect(FAR struct mfrc522_dev_s *dev)
{
  int ret;
  uint8_t buffer_atqa[2];
  uint8_t length = sizeof(buffer_atqa);

  // Reset baud rates
  mfrc522_writeu8(dev, MFRC522_TX_MODE_REG, 0x00);
  mfrc522_writeu8(dev, MFRC522_TX_MODE_REG, 0x00);
  // Reset ModWidthReg
  mfrc522_writeu8(dev, MFRC522_MOD_WIDTH_REG, 0x26);

  /* Send a REQA command */

  ret = mfrc522_picc_request_a(dev, buffer_atqa, length);
  return (ret == OK || ret == -EBUSY);
}

/**
 * Simple wrapper around PICC_Select.
 * Returns true if a UID could be read.
 * Remember to call PICC_IsNewCardPresent(), PICC_RequestA() or PICC_WakeupA() first.
 * The read UID is available in the class variable uid.
 * 
 * @return bool
 */
bool PICC_ReadCardSerial(FAR struct mfrc522_dev_s *dev) {
  int result = mfrc522_picc_select(dev, &uid, 0);
  return (result == OK);
} // End 

/****************************************************************************
 * Name: mfrc522_picc_select
 *
 * Description:
 *   Selects a near Card and read its UID.
 *
 * Input Parameters:
 *
 * Returned Value: OK or -ETIMEDOUT
 *
 ****************************************************************************/

int mfrc522_picc_select(FAR struct mfrc522_dev_s *dev,
                        FAR struct picc_uid_s *uid, uint8_t validbits)
{
  bool uid_complete;
  bool select_done;
  bool use_cascade_tag;
  uint8_t cascade_level = 1;
  int result;
  uint8_t i;
  uint8_t value;
  uint8_t count;

  /* The first index in uid->data[] that is used in the current Cascade Level */

  uint8_t uid_index;

  /* The number of known UID bits in the current Cascade Level. */

  uint8_t curr_level_known_bits;

  /* The SELECT/ANTICOLLISION uses a 7 byte standard frame + 2 bytes CRC_A */

  uint8_t buffer[9];

  /* The number of bytes used in the buffer, number bytes on FIFO */

  uint8_t buffer_used;

  /* Used to defines the bit position for the first bit received */

  uint8_t rxalign;

  /* The number of valid bits in the last transmitted byte. */

  uint8_t txlastbits;

  uint8_t *resp_buf;
  uint8_t resp_len;

  /* Sanity check */

  if (validbits > 80)
    {
      return -EINVAL;
    }

  /* Force clear of received bits if a collision is detected */

  value = mfrc522_readu8(dev, MFRC522_COLL_REG);
  mfrc522_writeu8(dev, MFRC522_COLL_REG, value & MFRC522_VALUES_AFTER_COLL);

  /* Repeat cascade level loop until we have a complete UID */

  uid_complete = false;
  while (!uid_complete)
    {
      uint8_t bytes_to_copy;

      /* Set the Cascade Level in the SEL byte, find out if we need to use the
       * Cascade Tag in byte 2.
       */

      switch (cascade_level)
        {
        case 1:
          buffer[0] = PICC_CMD_SEL_CL1;
          uid_index = 0;

          /* When we know that the UID has more than 4 bytes */

          use_cascade_tag = validbits && (uid->size > 4);
          break;

        case 2:
          buffer[0] = PICC_CMD_SEL_CL2;
          uid_index = 3;

          /* When we know that the UID has more than 7 bytes */

          use_cascade_tag = validbits && (uid->size > 7);
          break;

        case 3:
          buffer[0] = PICC_CMD_SEL_CL3;
          uid_index = 6;
          use_cascade_tag = false;
          break;

        default:
          return -EIO;          /* Internal error */
        }

      /* How many UID bits are known in this Cascade Level? */

      curr_level_known_bits = validbits - (8 * uid_index);
      if (curr_level_known_bits < 0)
        {
          curr_level_known_bits = 0;
        }

      /* Copy the known bits from uid->uid_data[] to buffer[] */

      i = 2;                    /* destination index in buffer[] */
      if (use_cascade_tag)
        {
          buffer[i++] = PICC_CMD_CT;
        }

      /* Number of bytes needed to represent the known bits for this level */

      bytes_to_copy = curr_level_known_bits / 8 +
                      (curr_level_known_bits % 8 ? 1 : 0);

      if (bytes_to_copy)
        {
          /* Max 4 bytes in each Cascade Level. Only 3 left if we use the
           * Cascade Tag.
           */

          uint8_t max_bytes = use_cascade_tag ? 3 : 4;

          if (bytes_to_copy > max_bytes)
            {
              bytes_to_copy = max_bytes;
            }

          for (count = 0; count < bytes_to_copy; count++)
            {
              buffer[i++] = uid->uid_data[uid_index + count];
            }
        }

      /* Now that the data has been copied we need to include the 8 bits in CT
       * in curr_level_known_bits.
       */

      if (use_cascade_tag)
        {
          curr_level_known_bits += 8;
        }

      /* Repeat anti collision loop until we can transmit all UID bits + BCC
       * and receive a SAK - max 32 iterations.
       */

      select_done = false;
      while (!select_done)
        {
          /* Find out how many bits and bytes to send and receive. */

          if (curr_level_known_bits >= 32)
            {
              /* All UID bits in this Cascade Level are known. This is a
               * SELECT.
               */

              /* NVB - Number of Valid Bits: Seven whole bytes */

              buffer[1] = 0x70;

              /* Calculate BCC - Block Check Character */

              buffer[6] = buffer[2] ^ buffer[3] ^ buffer[4] ^ buffer[5];

              /* Calculate CRC_A */

              result = mfrc522_calc_crc(dev, buffer, 7, &buffer[7]);
              if (result != OK)
                {
                  return result;
                }

              txlastbits = 0;   /* 0 => All 8 bits are valid. */
              buffer_used = 9;

              /* Store response in the last 3 bytes of buffer (BCC and CRC_A -
               * not needed after tx).
               */

              resp_buf = &buffer[6];
              resp_len = 3;
            }
          else
            {
              /* This is an ANTICOLLISION */

              txlastbits = curr_level_known_bits % 8;

              /* Number of whole bytes in the UID part. */

              count = curr_level_known_bits / 8;
              i = 2 + count;

              /* NVB - Number of Valid Bits */

              buffer[1] = (i << 4) + txlastbits;
              buffer_used = i + (txlastbits ? 1 : 0);

              /* Store response in the unused part of buffer */

              resp_buf = &buffer[i];
              resp_len = sizeof(buffer) - i;
            }

          /* Set bit adjustments */

          rxalign = txlastbits;
          mfrc522_writeu8(dev, MFRC522_BIT_FRAMING_REG,
                          (rxalign << 4) + txlastbits);

          /* Transmit the buffer and receive the response */

          result = mfrc522_transcv_data(dev, buffer, buffer_used, resp_buf,
                                        &resp_len, &txlastbits, rxalign, false);

          /* More than one PICC in the field => collision */

          if (result == -EBUSY)
            {
              uint8_t coll_pos;
              uint8_t coll_reg = mfrc522_readu8(dev, MFRC522_COLL_REG);

              /* CollPosNotValid */

              if (coll_reg & 0x20)
                {
                  /* Without a valid collision position we cannot continue */

                  return -EBUSY;
                }

              coll_pos = coll_reg & 0x1F; /* Values 0-31, 0 means bit 32. */
              if (coll_pos == 0)
                {
                  coll_pos = 32;
                }

              if (coll_pos <= curr_level_known_bits)
                {
                  /* No progress - should not happen */

                  return -EIO;
                }

              /* Choose the PICC with the bit set. */

              curr_level_known_bits = coll_pos;

              /* The bit to modify */

              count = (curr_level_known_bits - 1) % 8;

              /* First byte is index 0. */

              i = 1 + (curr_level_known_bits / 8) + (count ? 1 : 0);
              buffer[i] |= (1 << count);
            }
          else if (result != OK)
            {
              return result;
            }
          else                  /* OK */
            {
              /* This was a SELECT. */

              if (curr_level_known_bits >= 32)
                {
                  /* No more collision */

                  select_done = true;
                }
              else
                {
                  /* This was an ANTICOLLISION. */
                  /* We have all 32 bits of the UID in this Cascade Level */

                  curr_level_known_bits = 32;

                  /* Run loop again to do the SELECT */
                }
            }
        }

      /* We do not check the CBB - it was constructed by us above. */
      /* Copy the found UID bytes from buffer[] to uid->uid_data[] */

DBG("%d) b[0..3] = %2X, %2X, %2X, %2X\n", cascade_level, buffer[2], buffer[3], buffer[4], buffer[5]);
	  

      i = (buffer[2] == PICC_CMD_CT) ? 3 : 2;   /* source index in buffer[] */
      bytes_to_copy = (buffer[2] == PICC_CMD_CT) ? 3 : 4;

      for (count = 0; count < bytes_to_copy; count++)
        {
          uid->uid_data[uid_index + count] = buffer[i++];
        }

      /* Check response SAK (Select Acknowledge) */

      if (resp_len != 3 || txlastbits != 0)
        {
          /* SAK must be exactly 24 bits (1 byte + CRC_A). */

          return -EIO;
        }

      /* Verify CRC_A - do our own calculation and store the control in
       * buffer[2..3] - those bytes are not needed anymore.
       */

      result = mfrc522_calc_crc(dev, resp_buf, 1, &buffer[2]);
      if (result != OK)
        {
          return result;
        }

      /* Is it correct */

      if ((buffer[2] != resp_buf[1]) || (buffer[3] != resp_buf[2]))
        {
          return -EINVAL;
        }

      /* Cascade bit set - UID not complete yes */

      if (resp_buf[0] & 0x04)
        {
          cascade_level++;
        }
      else
        {
          uid_complete = true;
          uid->sak = resp_buf[0];
        }
    }

  /* Set correct uid->size */

  uid->size = 3 * cascade_level + 1;

  return OK;
}


// ----VVV----

/**
 * Instructs a PICC in state ACTIVE(*) to go to state HALT.
 *
 * @return OK on success, STATUS_??? otherwise.
 */ 
int PICC_HaltA(FAR struct mfrc522_dev_s *dev) {
  int result;
  uint8_t buffer[4];
  
  // Build command buffer
  buffer[0] = PICC_CMD_HLTA;
  buffer[1] = 0;
  // Calculate CRC_A
  result = mfrc522_calc_crc(dev, buffer, 2, &buffer[2]);
  if (result != OK) {
    return result;
  }
  
  // Send the command.
  // The standard says:
  //    If the PICC responds with any modulation during a period of 1 ms after the end of the frame containing the
  //    HLTA command, this response shall be interpreted as 'not acknowledge'.
  // We interpret that this way: Only STATUS_TIMEOUT is a success.
  result = mfrc522_transcv_data(dev, buffer, sizeof(buffer), NULL, 0, NULL, 0, false);
  if (result == -ETIMEDOUT) {
    return OK;
  }
  if (result == OK) { // That is ironically NOT ok in this case ;-)
    return -EIO;
  }
  return result;
} // End PICC_HaltA()

/////////////////////////////////////////////////////////////////////////////////////
// Functions for communicating with MIFARE PICCs
/////////////////////////////////////////////////////////////////////////////////////

/**
 * Executes the MFRC522 MFAuthent command.
 * This command manages MIFARE authentication to enable a secure communication to any MIFARE Mini, MIFARE 1K and MIFARE 4K card.
 * The authentication is described in the MFRC522 datasheet section 10.3.1.9 and http://www.nxp.com/documents/data_sheet/MF1S503x.pdf section 10.1.
 * For use with MIFARE Classic PICCs.
 * The PICC must be selected - ie in state ACTIVE(*) - before calling this function.
 * Remember to call PCD_StopCrypto1() after communicating with the authenticated PICC - otherwise no new communications can start.
 * 
 * All keys are set to FFFFFFFFFFFFh at chip delivery.
 * 
 * @return OK on success, STATUS_??? otherwise. Probably -ETIMEDOUT if you supply the wrong key.
 */
int PCD_Authenticate(FAR struct mfrc522_dev_s *dev,
                      uint8_t command,   ///< PICC_CMD_MF_AUTH_KEY_A or PICC_CMD_MF_AUTH_KEY_B
                      uint8_t blockAddr,   ///< The block number. See numbering in the comments in the .h file.
                      MIFARE_Key *key,  ///< Pointer to the Crypteo1 key to use (6 bytes)
                      struct picc_uid_s *uid      ///< Pointer to Uid struct. The first 4 bytes of the UID is used.
){
  uint8_t waitIRq = 0x10;    // IdleIRq
  
  // Build command buffer
  uint8_t sendData[12];
  sendData[0] = command;
  sendData[1] = blockAddr;
  for (uint8_t i = 0; i < MF_KEY_SIZE; i++) {  // 6 key bytes
    sendData[2+i] = key->keyByte[i];
  }
  // Use the last uid bytes as specified in http://cache.nxp.com/documents/application_note/AN10927.pdf
  // section 3.2.5 "MIFARE Classic Authentication".
  // The only missed case is the MF1Sxxxx shortcut activation,
  // but it requires cascade tag (CT) byte, that is not part of uid.
  for (uint8_t i = 0; i < 4; i++) {        // The last 4 bytes of the UID
    sendData[8+i] = uid->uid_data[i+uid->size-4];
  }
TRC("%s:%d\n", __func__, __LINE__);
  
  // Start the authentication.
  return mfrc522_comm_picc(dev, MFRC522_MF_AUTH_CMD, waitIRq, &sendData[0], sizeof(sendData)
                               , NULL, NULL, NULL, 0, false);
} // End PCD_Authenticate()

/**
 * Used to exit the PCD from its authenticated state.
 * Remember to call this function after communicating with an authenticated PICC - otherwise no new communications can start.
 */
void PCD_StopCrypto1(FAR struct mfrc522_dev_s *dev) {
  // Clear MFCrypto1On bit
  PCD_ClearRegisterBitMask(dev, MFRC522_STATUS2_REG, 0x08); // MFRC522_STATUS2_REG[7..0] bits are: TempSensClear I2CForceHS reserved reserved MFCrypto1On ModemState[2:0]
} // End PCD_StopCrypto1()

/**
 * Reads 16 bytes (+ 2 bytes CRC_A) from the active PICC.
 * 
 * For MIFARE Classic the sector containing the block must be authenticated before calling this function.
 * 
 * For MIFARE Ultralight only addresses 00h to 0Fh are decoded.
 * The MF0ICU1 returns a NAK for higher addresses.
 * The MF0ICU1 responds to the READ command by sending 16 bytes starting from the page address defined by the command argument.
 * For example; if blockAddr is 03h then pages 03h, 04h, 05h, 06h are returned.
 * A roll-back is implemented: If blockAddr is 0Eh, then the contents of pages 0Eh, 0Fh, 00h and 01h are returned.
 * 
 * The buffer must be at least 18 bytes because a CRC_A is also returned.
 * Checks the CRC_A before returning OK.
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_Read( FAR struct mfrc522_dev_s *dev,
                      uint8_t blockAddr,   ///< MIFARE Classic: The block (0-0xff) number. MIFARE Ultralight: The first page to return data from.
                      uint8_t *buffer,   ///< The buffer to store the data in
                      uint8_t *bufferSize  ///< Buffer size, at least 18 bytes. Also number of bytes returned if OK.
) {
  int result;
  
  // Sanity check
  if (buffer == NULL || *bufferSize < 18) {
    return -ENOBUFS;
  }
  
  // Build command buffer
  buffer[0] = PICC_CMD_MF_READ;
  buffer[1] = blockAddr;
  // Calculate CRC_A
  result = mfrc522_calc_crc(dev, buffer, 2, &buffer[2]);
  if (result != OK) {
    return result;
  }
  
  // Transmit the buffer and receive the response, validate CRC_A.
  return mfrc522_transcv_data(dev, buffer, 4, buffer, bufferSize, NULL, 0, true);
} // End MIFARE_Read()

/**
 * Writes 16 bytes to the active PICC.
 * 
 * For MIFARE Classic the sector containing the block must be authenticated before calling this function.
 * 
 * For MIFARE Ultralight the operation is called "COMPATIBILITY WRITE".
 * Even though 16 bytes are transferred to the Ultralight PICC, only the least significant 4 bytes (bytes 0 to 3)
 * are written to the specified address. It is recommended to set the remaining bytes 04h to 0Fh to all logic 0.
 * * 
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_Write(FAR struct mfrc522_dev_s *dev,
                      uint8_t blockAddr, ///< MIFARE Classic: The block (0-0xff) number. MIFARE Ultralight: The page (2-15) to write to.
                      uint8_t *buffer, ///< The 16 bytes to write to the PICC
                      uint8_t bufferSize ///< Buffer size, must be at least 16 bytes. Exactly 16 bytes are written.
) {
  int result;
  
  // Sanity check
  if (buffer == NULL || bufferSize < 16) {
    return -EINVAL;
  }
  
  // Mifare Classic protocol requires two communications to perform a write.
  // Step 1: Tell the PICC we want to write to block blockAddr.
  uint8_t cmdBuffer[2];
  cmdBuffer[0] = PICC_CMD_MF_WRITE;
  cmdBuffer[1] = blockAddr;
  result = PCD_MIFARE_Transceive(dev, cmdBuffer, 2, false); // Adds CRC_A and checks that the response is MF_ACK.
  if (result != OK) {
    return result;
  }
  
  // Step 2: Transfer the data
  result = PCD_MIFARE_Transceive(dev, buffer, bufferSize, false); // Adds CRC_A and checks that the response is MF_ACK.
  if (result != OK) {
    return result;
  }
  
  return OK;
} // End MIFARE_Write()

/**
 * Writes a 4 byte page to the active MIFARE Ultralight PICC.
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_Ultralight_Write(FAR struct mfrc522_dev_s *dev,
                            uint8_t page,    ///< The page (2-15) to write to.
                            uint8_t *buffer, ///< The 4 bytes to write to the PICC
                            uint8_t bufferSize ///< Buffer size, must be at least 4 bytes. Exactly 4 bytes are written.
) {
  int result;
  
  // Sanity check
  if (buffer == NULL || bufferSize < 4) {
    return -EINVAL;
  }
  
  // Build commmand buffer
  uint8_t cmdBuffer[6];
  cmdBuffer[0] = PICC_CMD_UL_WRITE;
  cmdBuffer[1] = page;
  memcpy(&cmdBuffer[2], buffer, 4);
  
  // Perform the write
  result = PCD_MIFARE_Transceive(dev, cmdBuffer, 6, false); // Adds CRC_A and checks that the response is MF_ACK.
  if (result != OK) {
    return result;
  }
  return OK;
} // End MIFARE_Ultralight_Write()

/**
 * MIFARE Decrement subtracts the delta from the value of the addressed block, and stores the result in a volatile memory.
 * For MIFARE Classic only. The sector containing the block must be authenticated before calling this function.
 * Only for blocks in "value block" mode, ie with access bits [C1 C2 C3] = [110] or [001].
 * Use MIFARE_Transfer() to store the result in a block.
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_Decrement(FAR struct mfrc522_dev_s *dev,
                        uint8_t blockAddr, ///< The block (0-0xff) number.
                        int32_t delta   ///< This number is subtracted from the value of block blockAddr.
) {
  return MIFARE_TwoStepHelper(dev, PICC_CMD_MF_DECREMENT, blockAddr, delta);
} // End MIFARE_Decrement()

/**
 * MIFARE Increment adds the delta to the value of the addressed block, and stores the result in a volatile memory.
 * For MIFARE Classic only. The sector containing the block must be authenticated before calling this function.
 * Only for blocks in "value block" mode, ie with access bits [C1 C2 C3] = [110] or [001].
 * Use MIFARE_Transfer() to store the result in a block.
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_Increment(FAR struct mfrc522_dev_s *dev,
                        uint8_t blockAddr, ///< The block (0-0xff) number.
                        int32_t delta   ///< This number is added to the value of block blockAddr.
) {
  return MIFARE_TwoStepHelper(dev, PICC_CMD_MF_INCREMENT, blockAddr, delta);
} // End MIFARE_Increment()

/**
 * MIFARE Restore copies the value of the addressed block into a volatile memory.
 * For MIFARE Classic only. The sector containing the block must be authenticated before calling this function.
 * Only for blocks in "value block" mode, ie with access bits [C1 C2 C3] = [110] or [001].
 * Use MIFARE_Transfer() to store the result in a block.
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_Restore(FAR struct mfrc522_dev_s *dev,
                          uint8_t blockAddr ///< The block (0-0xff) number.
) {
  // The datasheet describes Restore as a two step operation, but does not explain what data to transfer in step 2.
  // Doing only a single step does not work, so I chose to transfer 0L in step two.
  return MIFARE_TwoStepHelper(dev, PICC_CMD_MF_RESTORE, blockAddr, 0L);
} // End MIFARE_Restore()

/**
 * Helper function for the two-step MIFARE Classic protocol operations Decrement, Increment and Restore.
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_TwoStepHelper(FAR struct mfrc522_dev_s *dev,
                          uint8_t command, ///< The command to use
                          uint8_t blockAddr, ///< The block (0-0xff) number.
                          int32_t data    ///< The data to transfer in step 2
) {
  int result;
  uint8_t cmdBuffer[2]; // We only need room for 2 bytes.
  
  // Step 1: Tell the PICC the command and block address
  cmdBuffer[0] = command;
  cmdBuffer[1] = blockAddr;
  result = PCD_MIFARE_Transceive(dev, cmdBuffer, 2, false); // Adds CRC_A and checks that the response is MF_ACK.
  if (result != OK) {
    return result;
  }
  
  // Step 2: Transfer the data
  result = PCD_MIFARE_Transceive(dev, (uint8_t *)&data, 4, true); // Adds CRC_A and accept timeout as success.
  if (result != OK) {
    return result;
  }
  
  return OK;
} // End MIFARE_TwoStepHelper()

/**
 * MIFARE Transfer writes the value stored in the volatile memory into one MIFARE Classic block.
 * For MIFARE Classic only. The sector containing the block must be authenticated before calling this function.
 * Only for blocks in "value block" mode, ie with access bits [C1 C2 C3] = [110] or [001].
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_Transfer(FAR struct mfrc522_dev_s *dev,
                 uint8_t blockAddr ///< The block (0-0xff) number.
) {
  int result;
  uint8_t cmdBuffer[2]; // We only need room for 2 bytes.
  
  // Tell the PICC we want to transfer the result into block blockAddr.
  cmdBuffer[0] = PICC_CMD_MF_TRANSFER;
  cmdBuffer[1] = blockAddr;
  result = PCD_MIFARE_Transceive(dev, cmdBuffer, 2, false); // Adds CRC_A and checks that the response is MF_ACK.
  if (result != OK) {
    return result;
  }
  return OK;
} // End MIFARE_Transfer()

/**
 * Helper routine to read the current value from a Value Block.
 * 
 * Only for MIFARE Classic and only for blocks in "value block" mode, that
 * is: with access bits [C1 C2 C3] = [110] or [001]. The sector containing
 * the block must be authenticated before calling this function. 
 * 
 * @param[in]   blockAddr   The block (0x00-0xff) number.
 * @param[out]  value       Current value of the Value Block.
 * @return OK on success, STATUS_??? otherwise.
  */
int MIFARE_GetValue(FAR struct mfrc522_dev_s *dev,
                  uint8_t blockAddr, int32_t *value
) {
  int status;
  uint8_t buffer[18];
  uint8_t size = sizeof(buffer);
  
  // Read the block
  status = MIFARE_Read(dev, blockAddr, buffer, &size);
  if (status == OK) {
    // Extract the value
    *value = ((int32_t)(buffer[3])<<24) | ((int32_t)(buffer[2])<<16) | ((int32_t)(buffer[1])<<8) | (int32_t)(buffer[0]);
  }
  return status;
} // End MIFARE_GetValue()

/**
 * Helper routine to write a specific value into a Value Block.
 * 
 * Only for MIFARE Classic and only for blocks in "value block" mode, that
 * is: with access bits [C1 C2 C3] = [110] or [001]. The sector containing
 * the block must be authenticated before calling this function. 
 * 
 * @param[in]   blockAddr   The block (0x00-0xff) number.
 * @param[in]   value       New value of the Value Block.
 * @return OK on success, STATUS_??? otherwise.
 */
int MIFARE_SetValue(FAR struct mfrc522_dev_s *dev,
                  uint8_t blockAddr, int32_t value) {
  uint8_t buffer[18];
  
  // Translate the int32_t into 4 bytes; repeated 2x in value block
  buffer[0] = buffer[ 8] = (value & 0xFF);
  buffer[1] = buffer[ 9] = (value & 0xFF00) >> 8;
  buffer[2] = buffer[10] = (value & 0xFF0000) >> 16;
  buffer[3] = buffer[11] = (value & 0xFF000000) >> 24;
  // Inverse 4 bytes also found in value block
  buffer[4] = ~buffer[0];
  buffer[5] = ~buffer[1];
  buffer[6] = ~buffer[2];
  buffer[7] = ~buffer[3];
  // Address 2x with inverse address 2x
  buffer[12] = buffer[14] = blockAddr;
  buffer[13] = buffer[15] = ~blockAddr;
  
  // Write the whole data block
  return MIFARE_Write(dev, blockAddr, buffer, 16);
} // End MIFARE_SetValue()

/**
 * Authenticate with a NTAG216.
 * 
 * Only for NTAG216. First implemented by Gargantuanman.
 * 
 * @param[in]   passWord   password.
 * @param[in]   pACK       result success???.
 * @return OK on success, STATUS_??? otherwise.
 */
int PCD_NTAG216_AUTH(FAR struct mfrc522_dev_s *dev,
                     uint8_t* passWord, uint8_t pACK[]) //Authenticate with 32bit password
{
  // TODO: Fix cmdBuffer length and rxlength. They really should match.
  //       (Better still, rxlength should not even be necessary.)

  int result;
  uint8_t        cmdBuffer[18]; // We need room for 16 bytes data and 2 bytes CRC_A.
  
  cmdBuffer[0] = 0x1B; //Comando de autentificacion
  
  for (uint8_t i = 0; i<4; i++)
    cmdBuffer[i+1] = passWord[i];
  
  result = mfrc522_calc_crc(dev, cmdBuffer, 5, &cmdBuffer[5]);
  
  if (result!=OK) {
    return result;
  }
  
  // Transceive the data, store the reply in cmdBuffer[]
  uint8_t waitIRq    = 0x30; // RxIRq and IdleIRq
//  uint8_t cmdBufferSize  = sizeof(cmdBuffer);
  uint8_t validBits    = 0;
  uint8_t rxlength   = 5;
  result = mfrc522_comm_picc(dev, MFRC522_TRANSCV_CMD, waitIRq, cmdBuffer, 7, cmdBuffer, &rxlength, &validBits, 0, false);
  
  pACK[0] = cmdBuffer[0];
  pACK[1] = cmdBuffer[1];
  
  if (result!=OK) {
    return result;
  }
  
  return OK;
} // End PCD_NTAG216_AUTH()


/////////////////////////////////////////////////////////////////////////////////////
// Support functions
/////////////////////////////////////////////////////////////////////////////////////

/**
 * Wrapper for MIFARE protocol communication.
 * Adds CRC_A, executes the Transceive command and checks that the response is MF_ACK or a timeout.
 * 
 * @return OK on success, STATUS_??? otherwise.
 */
int PCD_MIFARE_Transceive(FAR struct mfrc522_dev_s *dev,
                        uint8_t *sendData,   ///< Pointer to the data to transfer to the FIFO. Do NOT include the CRC_A.
                        uint8_t sendLen,   ///< Number of bytes in sendData.
                        bool acceptTimeout  ///< True => A timeout is also success
) {
  int result;
  uint8_t cmdBuffer[18]; // We need room for 16 bytes data and 2 bytes CRC_A.
  
  // Sanity check
  if (sendData == NULL || sendLen > 16) {
    return -EINVAL;
  }
  
  // Copy sendData[] to cmdBuffer[] and add CRC_A
  memcpy(cmdBuffer, sendData, sendLen);
  result = mfrc522_calc_crc(dev,cmdBuffer, sendLen, &cmdBuffer[sendLen]);
  if (result != OK) { 
    return result;
  }
  sendLen += 2;
  
  // Transceive the data, store the reply in cmdBuffer[]
  uint8_t waitIRq = 0x30;    // RxIRq and IdleIRq
  uint8_t cmdBufferSize = sizeof(cmdBuffer);
  uint8_t validBits = 0;
  result = mfrc522_comm_picc(dev, MFRC522_TRANSCV_CMD, waitIRq, cmdBuffer, sendLen, 
                         cmdBuffer, &cmdBufferSize, &validBits, 0, false);
  if (acceptTimeout && result == -ETIMEDOUT) {
    return OK;
  }
  if (result != OK) {
    return result;
  }
  // The PICC must reply with a 4 bit ACK
  if (cmdBufferSize != 1 || validBits != 4) {
    return -EIO;
  }
  if (cmdBuffer[0] != MF_ACK) {
    return -EMIFARE_NACK;
  }
  return OK;
} // End PCD_MIFARE_Transceive()

/**
 * Returns a __FlashStringHelper pointer to a status code name.
 * 
 * @return const __FlashStringHelper *
 */
const char *GetStatusCodeName(FAR struct mfrc522_dev_s *dev,
                          int code  ///< One of the StatusCode enums.
) {
  switch (code) {
    case OK:       return "Success.";
    case -EIO:      return "Error in communication.";
    case -ECOLLISION:    return "Collission detected.";
    case -ETIMEDOUT:    return "Timeout in communication.";
    case -ENOBUFS:    return "A buffer is not big enough.";
    //case STATUS_INTERNAL_ERROR: return "Internal error in the code. Should not happen.";
    case -EINVAL:    return "Invalid argument.";
    //case STATUS_CRC_WRONG:    return "The CRC_A does not match.";
    case -EMIFARE_NACK:  return "A MIFARE PICC responded with NAK.";
    default:          return "Unknown error";
  }
} // End GetStatusCodeName()

/**
 * Translates the SAK (Select Acknowledge) to a PICC type.
 * 
 * @return uint8_t
 */
uint8_t PICC_GetType(FAR struct mfrc522_dev_s *dev,
                  uint8_t sak   ///< The SAK byte returned from PICC_Select().
) {
  // http://www.nxp.com/documents/application_note/AN10833.pdf 
  // 3.2 Coding of Select Acknowledge (SAK)
  // ignore 8-bit (iso14443 starts with LSBit = bit 1)
  // fixes wrong type for manufacturer Infineon (http://nfc-tools.org/index.php?title=ISO14443A)
  sak &= 0x7F;
  switch (sak) {
    case 0x04:  return PICC_TYPE_NOT_COMPLETE;  // UID not complete
    case 0x09:  return PICC_TYPE_MIFARE_MINI;
    case 0x08:  return PICC_TYPE_MIFARE_1K;
    case 0x18:  return PICC_TYPE_MIFARE_4K;
    case 0x00:  return PICC_TYPE_MIFARE_UL;
    case 0x10:
    case 0x11:  return PICC_TYPE_MIFARE_PLUS;
    case 0x01:  return PICC_TYPE_TNP3XXX;
    case 0x20:  return PICC_TYPE_ISO_14443_4;
    case 0x40:  return PICC_TYPE_ISO_18092;
    default:  return PICC_TYPE_UNKNOWN;
  }
} // End PICC_GetType()

/**
 * Returns a __FlashStringHelper pointer to the PICC type name.
 * 
 * @return const __FlashStringHelper *
 */
const char *PICC_GetTypeName(FAR struct mfrc522_dev_s *dev,
                          uint8_t piccType ///< One of the PICC_Type enums.
) {
  switch (piccType) {
    case PICC_TYPE_ISO_14443_4:   return "PICC compliant with ISO/IEC 14443-4";
    case PICC_TYPE_ISO_18092:   return "PICC compliant with ISO/IEC 18092 (NFC)";
    case PICC_TYPE_MIFARE_MINI:   return "MIFARE Mini, 320 bytes";
    case PICC_TYPE_MIFARE_1K:   return "MIFARE 1KB";
    case PICC_TYPE_MIFARE_4K:   return "MIFARE 4KB";
    case PICC_TYPE_MIFARE_UL:   return "MIFARE Ultralight or Ultralight C";
    case PICC_TYPE_MIFARE_PLUS:   return "MIFARE Plus";
    case PICC_TYPE_MIFARE_DESFIRE:  return "MIFARE DESFire";
    case PICC_TYPE_TNP3XXX:     return "MIFARE TNP3XXX";
    case PICC_TYPE_NOT_COMPLETE:  return "SAK indicates UID is not complete.";
    case PICC_TYPE_UNKNOWN:
    default:            return "Unknown type";
  }
} // End PICC_GetTypeName()

/**
 * Dumps debug info about the connected PCD to Serial.
 * Shows all known firmware versions
 */
void PCD_DumpVersionToSerial(FAR struct mfrc522_dev_s *dev) {
  // Get the MFRC522 firmware version
  uint8_t v = mfrc522_readu8(dev, MFRC522_VERSION_REG);
  printf("Firmware Version: 0x%X\n", v);
  // Lookup which version
  switch(v) {
    case 0x88: printf(" = (clone)\n");  break;
    case 0x90: printf(" = v0.0\n");     break;
    case 0x91: printf(" = v1.0\n");     break;
    case 0x92: printf(" = v2.0\n");     break;
    case 0x12: printf(" = counterfeit chip\n");     break;
    default:   printf(" = (unknown)\n");
  }
  // When 0x00 or 0xFF is returned, communication probably failed
  if ((v == 0x00) || (v == 0xFF))
    printf("WARNING: Communication failure, is the MFRC522 properly connected?\n");
} // End PCD_DumpVersionToSerial()

/**
 * Dumps debug info about the selected PICC to Serial.
 * On success the PICC is halted after dumping the data.
 * For MIFARE Classic the factory default key of 0xFFFFFFFFFFFF is tried.  
 *
 * @DEPRECATED Kept for bakward compatibility
 */
void PICC_DumpToSerial(FAR struct mfrc522_dev_s *dev,
                     struct picc_uid_s *uid  ///< Pointer to Uid struct returned from a successful PICC_Select().
) {
  MIFARE_Key key;
  
  // Dump UID, SAK and Type
  PICC_DumpDetailsToSerial(dev, uid);
  
  // Dump contents
  uint8_t piccType = PICC_GetType(dev, uid->sak);
  switch (piccType) {
    case PICC_TYPE_MIFARE_MINI:
    case PICC_TYPE_MIFARE_1K:
    case PICC_TYPE_MIFARE_4K:
      // All keys are set to FFFFFFFFFFFFh at chip delivery from the factory.
      for (uint8_t i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
      }
      PICC_DumpMifareClassicToSerial(dev, uid, piccType, &key);
      break;
      
    case PICC_TYPE_MIFARE_UL:
      PICC_DumpMifareUltralightToSerial(dev);
      break;
      
    case PICC_TYPE_ISO_14443_4:
    case PICC_TYPE_MIFARE_DESFIRE:
    case PICC_TYPE_ISO_18092:
    case PICC_TYPE_MIFARE_PLUS:
    case PICC_TYPE_TNP3XXX:
      printf("Dumping memory contents not implemented for that PICC type.\n");
      break;
      
    case PICC_TYPE_UNKNOWN:
    case PICC_TYPE_NOT_COMPLETE:
    default:
      break; // No memory dump here
  }
  
  printf("\n");
  PICC_HaltA(dev); // Already done if it was a MIFARE Classic PICC.
} // End PICC_DumpToSerial()

/**
 * Dumps card info (UID,SAK,Type) about the selected PICC to Serial.
 *
 * @DEPRECATED kept for backward compatibility
 */
void PICC_DumpDetailsToSerial(FAR struct mfrc522_dev_s *dev,
                          struct picc_uid_s *uid ///< Pointer to Uid struct returned from a successful PICC_Select().
) {
  // UID
  printf("Card UID:");
  for (uint8_t i = 0; i < uid->size; i++) {
    printf(" %2X", uid->uid_data[i]);
  } 
  printf("\n");
  
  // SAK
  printf("Card SAK: %2X\n", uid->sak);
  
  // (suggested) PICC type
  uint8_t piccType = PICC_GetType(dev, uid->sak);
  printf("PICC type: %s\n", PICC_GetTypeName(dev, piccType));
} // End PICC_DumpDetailsToSerial()

/**
 * Dumps memory contents of a MIFARE Classic PICC.
 * On success the PICC is halted after dumping the data.
 */
void PICC_DumpMifareClassicToSerial(FAR struct mfrc522_dev_s *dev,
                               struct picc_uid_s *uid,  ///< Pointer to Uid struct returned from a successful PICC_Select().
                               uint8_t piccType,    ///< One of the PICC_Type enums.
                               MIFARE_Key *key   ///< Key A used for all sectors.
) {
  uint8_t no_of_sectors = 0;
  switch (piccType) {
    case PICC_TYPE_MIFARE_MINI:
      // Has 5 sectors * 4 blocks/sector * 16 bytes/block = 320 bytes.
      no_of_sectors = 5;
      break;
      
    case PICC_TYPE_MIFARE_1K:
      // Has 16 sectors * 4 blocks/sector * 16 bytes/block = 1024 bytes.
      no_of_sectors = 16;
      break;
      
    case PICC_TYPE_MIFARE_4K:
      // Has (32 sectors * 4 blocks/sector + 8 sectors * 16 blocks/sector) * 16 bytes/block = 4096 bytes.
      no_of_sectors = 40;
      break;
      
    default: // Should not happen. Ignore.
      break;
  }
  
  // Dump sectors, highest address first.
  if (no_of_sectors) {
    printf("Sector Block   0  1  2  3   4  5  6  7   8  9 10 11  12 13 14 15  AccessBits\n");
    for (int8_t i = no_of_sectors - 1; i >= 0; i--) {
      PICC_DumpMifareClassicSectorToSerial(dev, uid, key, i);
    }
  }
  PICC_HaltA(dev); // Halt the PICC before stopping the encrypted session.
  PCD_StopCrypto1(dev);
} // End PICC_DumpMifareClassicToSerial()

/**
 * Dumps memory contents of a sector of a MIFARE Classic PICC.
 * Uses PCD_Authenticate(), MIFARE_Read() and PCD_StopCrypto1.
 * Always uses PICC_CMD_MF_AUTH_KEY_A because only Key A can always read the sector trailer access bits.
 */
void PICC_DumpMifareClassicSectorToSerial(FAR struct mfrc522_dev_s *dev,
                                    struct picc_uid_s *uid,      ///< Pointer to Uid struct returned from a successful PICC_Select().
                                    MIFARE_Key *key,  ///< Key A for the sector.
                                    uint8_t sector     ///< The sector to dump, 0..39.
) {
  int status;
  uint8_t firstBlock;    // Address of lowest address to dump actually last block dumped)
  uint8_t no_of_blocks;    // Number of blocks in sector
  bool isSectorTrailer; // Set to true while handling the "last" (ie highest address) in the sector.
  
  // The access bits are stored in a peculiar fashion.
  // There are four groups:
  //    g[3]  Access bits for the sector trailer, block 3 (for sectors 0-31) or block 15 (for sectors 32-39)
  //    g[2]  Access bits for block 2 (for sectors 0-31) or blocks 10-14 (for sectors 32-39)
  //    g[1]  Access bits for block 1 (for sectors 0-31) or blocks 5-9 (for sectors 32-39)
  //    g[0]  Access bits for block 0 (for sectors 0-31) or blocks 0-4 (for sectors 32-39)
  // Each group has access bits [C1 C2 C3]. In this code C1 is MSB and C3 is LSB.
  // The four CX bits are stored together in a nible cx and an inverted nible cx_.
  uint8_t c1, c2, c3;    // Nibbles
  uint8_t c1_, c2_, c3_;   // Inverted nibbles
  bool invertedError;   // True if one of the inverted nibbles did not match
  uint8_t g[4];        // Access bits for each of the four groups.
  uint8_t group;       // 0-3 - active group for access bits
  bool firstInGroup;    // True for the first block dumped in the group
  
  // Determine position and size of sector.
  if (sector < 32) { // Sectors 0..31 has 4 blocks each
    no_of_blocks = 4;
    firstBlock = sector * no_of_blocks;
  }
  else if (sector < 40) { // Sectors 32-39 has 16 blocks each
    no_of_blocks = 16;
    firstBlock = 128 + (sector - 32) * no_of_blocks;
  }
  else { // Illegal input, no MIFARE Classic PICC has more than 40 sectors.
    return;
  }
    
  // Dump blocks, highest address first.
  uint8_t byteCount;
  uint8_t buffer[18];
  uint8_t blockAddr;
  isSectorTrailer = true;
  invertedError = false;  // Avoid "unused variable" warning.
  for (int8_t blockOffset = no_of_blocks - 1; blockOffset >= 0; blockOffset--) {
    blockAddr = firstBlock + blockOffset;
    // Sector number - only on first line
    if (isSectorTrailer) {
      if(sector < 10)
        printf("   "); // Pad with spaces
      else
        printf("  "); // Pad with spaces
      printf("%d   ", sector);
    }
    else {
      printf("       ");
    }
    // Block number
    if(blockAddr < 10)
      printf("   "); // Pad with spaces
    else {
      if(blockAddr < 100)
        printf("  "); // Pad with spaces
      else
        printf(" "); // Pad with spaces
    }
    printf("%d  ", blockAddr);
    // Establish encrypted communications before reading the first block
    if (isSectorTrailer) {
      status = PCD_Authenticate(dev, PICC_CMD_MF_AUTH_KEY_A, firstBlock, key, uid);
      if (status != OK) {
        printf("PCD_Authenticate() failed: %s\n", GetStatusCodeName(dev, status));
        return;
      }
    }
    // Read block
    byteCount = sizeof(buffer);
    status = MIFARE_Read(dev, blockAddr, buffer, &byteCount);
    if (status != OK) {
      printf("MIFARE_Read() failed: %s\n", GetStatusCodeName(dev, status));
      continue;
    }
    // Dump data
    for (uint8_t index = 0; index < 16; index++) {
      printf(" %2X", buffer[index]);
      if ((index % 4) == 3) {
        printf(" ");
      }
    }
    // Parse sector trailer data
    if (isSectorTrailer) {
      c1  = buffer[7] >> 4;
      c2  = buffer[8] & 0xF;
      c3  = buffer[8] >> 4;
      c1_ = buffer[6] & 0xF;
      c2_ = buffer[6] >> 4;
      c3_ = buffer[7] & 0xF;
      invertedError = (c1 != (~c1_ & 0xF)) || (c2 != (~c2_ & 0xF)) || (c3 != (~c3_ & 0xF));
      g[0] = ((c1 & 1) << 2) | ((c2 & 1) << 1) | ((c3 & 1) << 0);
      g[1] = ((c1 & 2) << 1) | ((c2 & 2) << 0) | ((c3 & 2) >> 1);
      g[2] = ((c1 & 4) << 0) | ((c2 & 4) >> 1) | ((c3 & 4) >> 2);
      g[3] = ((c1 & 8) >> 1) | ((c2 & 8) >> 2) | ((c3 & 8) >> 3);
      isSectorTrailer = false;
    }
    
    // Which access group is this block in?
    if (no_of_blocks == 4) {
      group = blockOffset;
      firstInGroup = true;
    }
    else {
      group = blockOffset / 5;
      firstInGroup = (group == 3) || (group != (blockOffset + 1) / 5);
    }
    
    if (firstInGroup) {
      // Print access bits
      printf(" [ %d %d %d]", (g[group] >> 2) & 1, (g[group] >> 1) & 1, (g[group] >> 0) & 1);
      if (invertedError) {
        printf(" Inverted access bits did not match! ");
      }
    }
    
    if (group != 3 && (g[group] == 1 || g[group] == 6)) { // Not a sector trailer, a value block
      int32_t value = ((int32_t)(buffer[3])<<24) | ((int32_t)(buffer[2])<<16) | ((int32_t)(buffer[1])<<8) | (int32_t)(buffer[0]);
      printf(" Value=0x%X Adr=0x%X", value, buffer[12]);
    }
    printf("\n");
  }
  
  return;
} // End PICC_DumpMifareClassicSectorToSerial()

/**
 * Dumps memory contents of a MIFARE Ultralight PICC.
 */
void PICC_DumpMifareUltralightToSerial(FAR struct mfrc522_dev_s *dev) {
  int status;
  uint8_t byteCount;
  uint8_t buffer[18];
  uint8_t i;
  
  printf("Page  0  1  2  3\n");
  // Try the mpages of the original Ultralight. Ultralight C has more pages.
  for (uint8_t page = 0; page < 16; page +=4) { // Read returns data for 4 pages at a time.
    // Read pages
    byteCount = sizeof(buffer);
    status = MIFARE_Read(dev, page, buffer, &byteCount);
    if (status != OK) {
      printf("MIFARE_Read() failed: %s\n", GetStatusCodeName(dev, status));
      break;
    }
    // Dump data
    for (uint8_t offset = 0; offset < 4; offset++) {
      i = page + offset;
      if(i < 10)
        printf("  "); // Pad with spaces
      else
        printf(" "); // Pad with spaces
      printf("%d  ", i);
      for (uint8_t index = 0; index < 4; index++) {
        i = 4 * offset + index;
        printf(" %2X", buffer[i]);
      }
      printf("\n");
    }
  }
} // End PICC_DumpMifareUltralightToSerial()

/**
 * Calculates the bit pattern needed for the specified access bits. In the [C1 C2 C3] tuples C1 is MSB (=4) and C3 is LSB (=1).
 */
void MIFARE_SetAccessBits(FAR struct mfrc522_dev_s *dev,
                  uint8_t *accessBitBuffer,  ///< Pointer to byte 6, 7 and 8 in the sector trailer. Bytes [0..2] will be set.
                  uint8_t g0,        ///< Access bits [C1 C2 C3] for block 0 (for sectors 0-31) or blocks 0-4 (for sectors 32-39)
                  uint8_t g1,        ///< Access bits C1 C2 C3] for block 1 (for sectors 0-31) or blocks 5-9 (for sectors 32-39)
                  uint8_t g2,        ///< Access bits C1 C2 C3] for block 2 (for sectors 0-31) or blocks 10-14 (for sectors 32-39)
                  uint8_t g3         ///< Access bits C1 C2 C3] for the sector trailer, block 3 (for sectors 0-31) or block 15 (for sectors 32-39)
) {
  uint8_t c1 = ((g3 & 4) << 1) | ((g2 & 4) << 0) | ((g1 & 4) >> 1) | ((g0 & 4) >> 2);
  uint8_t c2 = ((g3 & 2) << 2) | ((g2 & 2) << 1) | ((g1 & 2) << 0) | ((g0 & 2) >> 1);
  uint8_t c3 = ((g3 & 1) << 3) | ((g2 & 1) << 2) | ((g1 & 1) << 1) | ((g0 & 1) << 0);
  
  accessBitBuffer[0] = (~c2 & 0xF) << 4 | (~c1 & 0xF);
  accessBitBuffer[1] =          c1 << 4 | (~c3 & 0xF);
  accessBitBuffer[2] =          c3 << 4 | c2;
} // End MIFARE_SetAccessBits()


/**
 * Performs the "magic sequence" needed to get Chinese UID changeable
 * Mifare cards to allow writing to sector 0, where the card UID is stored.
 *
 * Note that you do not need to have selected the card through REQA or WUPA,
 * this sequence works immediately when the card is in the reader vicinity.
 * This means you can use this method even on "bricked" cards that your reader does
 * not recognise anymore (see MIFARE_UnbrickUidSector).
 * 
 * Of course with non-bricked devices, you're free to select them before calling this function.
 */
bool MIFARE_OpenUidBackdoor(FAR struct mfrc522_dev_s *dev, bool logErrors) {
  // Magic sequence:
  // > 50 00 57 CD (HALT + CRC)
  // > 40 (7 bits only)
  // < A (4 bits only)
  // > 43
  // < A (4 bits only)
  // Then you can write to sector 0 without authenticating
  
  PICC_HaltA(dev); // 50 00 57 CD

  uint8_t cmd = 0x40;
  uint8_t validBits = 7; /* Our command is only 7 bits. After receiving card response,
              this will contain amount of valid response bits. */
  uint8_t response[32]; // Card's response is written here
  uint8_t received;
  int status = mfrc522_transcv_data(dev, &cmd, (uint8_t)1, response, &received, &validBits, (uint8_t)0, false); // 40
  if(status != OK) {
    if(logErrors) {
      DBG("Card did not respond to 0x40 after HALT command. Are you sure it is a UID changeable one?\n");
      DBG("Error name: %s\n", GetStatusCodeName(dev, status));
    }
    return false;
  }
  if (received != 1 || response[0] != 0x0A) {
    if (logErrors) {
      DBG("Got bad response on backdoor 0x40 command: %X (%d valid bits)\n", response[0], validBits);
    }
    return false;
  }
  
  cmd = 0x43;
  validBits = 8;
  status = mfrc522_transcv_data(dev, &cmd, (uint8_t)1, response, &received, &validBits, (uint8_t)0, false); // 43
  if(status != OK) {
    if(logErrors) {
      DBG("Error in communication at command 0x43, after successfully executing 0x40\n");
      DBG("Error name: %s\n", GetStatusCodeName(dev, status));
    }
    return false;
  }
  if (received != 1 || response[0] != 0x0A) {
    if (logErrors) {
      DBG("Got bad response on backdoor 0x43 command: %X (%d valid bits)\n", response[0], validBits);
    }
    return false;
  }
  
  // You can now write to sector 0 without authenticating!
  return true;
} // End MIFARE_OpenUidBackdoor()

/**
 * Reads entire block 0, including all manufacturer data, and overwrites
 * that block with the new UID, a freshly calculated BCC, and the original
 * manufacturer data.
 *
 * It assumes a default KEY A of 0xFFFFFFFFFFFF.
 * Make sure to have selected the card before this function is called.
 */
bool MIFARE_SetUid(FAR struct mfrc522_dev_s *dev, uint8_t *newUid, uint8_t uidSize, bool logErrors) {
  
  // UID + BCC uint8_t can not be larger than 16 together
  if (!newUid || !uidSize || uidSize > 15) {
    if (logErrors) {
      DBG("New UID buffer empty, size 0, or size > 15 given\n");
    }
    return false;
  }
  
  // Authenticate for reading
  MIFARE_Key key = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
  int status = PCD_Authenticate(dev, PICC_CMD_MF_AUTH_KEY_A, (uint8_t)1, &key, &uid);
  if (status != OK) {
    
    if (status == -ETIMEDOUT) {
      // We get a read timeout if no card is selected yet, so let's select one
      
      // Wake the card up again if sleeping
//        uint8_t atqa_answer[2];
//        uint8_t atqa_size = 2;
//        mfrc522_picc_wakeup_a(atqa_answer, &atqa_size);
      
      if (!mfrc522_picc_detect(dev) || !PICC_ReadCardSerial(dev)) {
        DBG("No card was previously selected, and none are available. Failed to set UID.\n");
        return false;
      }
      
      status = PCD_Authenticate(dev, PICC_CMD_MF_AUTH_KEY_A, (uint8_t)1, &key, &uid);
      if (status != OK) {
        // We tried, time to give up
        if (logErrors) {
          DBG("Failed to authenticate to card for reading, could not set UID: \n");
          DBG("%s\n", GetStatusCodeName(dev, status));
        }
        return false;
      }
    }
    else {
      if (logErrors) {
        DBG("PCD_Authenticate() failed: %s\n", GetStatusCodeName(dev, status));
      }
      return false;
    }
  }
  
  // Read block 0
  uint8_t block0_buffer[18];
  uint8_t byteCount = sizeof(block0_buffer);
  status = MIFARE_Read(dev, (uint8_t)0, block0_buffer, &byteCount);
  if (status != OK) {
    if (logErrors) {
      DBG("MIFARE_Read() failed: %s\n", GetStatusCodeName(dev, status));
      DBG("Are you sure your KEY A for sector 0 is 0xFFFFFFFFFFFF?\n");
    }
    return false;
  }
  
  // Write new UID to the data we just read, and calculate BCC byte
  uint8_t bcc = 0;
  for (uint8_t i = 0; i < uidSize; i++) {
    block0_buffer[i] = newUid[i];
    bcc ^= newUid[i];
  }
  
  // Write BCC byte to buffer
  block0_buffer[uidSize] = bcc;
  
  // Stop encrypted traffic so we can send raw bytes
  PCD_StopCrypto1(dev);
  
  // Activate UID backdoor
  if (!MIFARE_OpenUidBackdoor(dev, logErrors)) {
    if (logErrors) {
      DBG("Activating the UID backdoor failed.\n");
    }
    return false;
  }
  
  // Write modified block 0 back to card
  status = MIFARE_Write(dev, (uint8_t)0, block0_buffer, (uint8_t)16);
  if (status != OK) {
    if (logErrors) {
      DBG("MIFARE_Write() failed: %s\n", GetStatusCodeName(dev, status));
    }
    return false;
  }
  
  // Wake the card up again
  uint8_t atqa_answer[2];
  uint8_t atqa_size = 2;
  mfrc522_picc_wakeup_a(dev, atqa_answer, &atqa_size);
  
  return true;
}

/**
 * Resets entire sector 0 to zeroes, so the card can be read again by readers.
 */
bool MIFARE_UnbrickUidSector(FAR struct mfrc522_dev_s *dev, bool logErrors) {
  MIFARE_OpenUidBackdoor(dev, logErrors);
  
  uint8_t block0_buffer[] = {0x01, 0x02, 0x03, 0x04, 0x04, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  
  
  // Write modified block 0 back to card
  int status = MIFARE_Write(dev, (uint8_t)0, block0_buffer, (uint8_t)16);
  if (status != OK) {
    if (logErrors) {
      DBG("MIFARE_Write() failed: %s\n", GetStatusCodeName(dev, status));
    }
    return false;
  }
  return true;
}





// ----AAA----


/****************************************************************************
 * Name: mfrc522_softreset
 *
 * Description:
 *   Send a software reset command
 *
 * Input Parameters: a pointer to mfrc522_dev_s structure
 *
 * Returned Value: none
 *
 ****************************************************************************/

void mfrc522_softreset(FAR struct mfrc522_dev_s *dev)
{
  /* Send a software reset command */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, MFRC522_SOFTRST_CMD);

  /* Wait the internal state machine to initialize */

  nxsig_usleep(50000);

  /* Wait for the PowerDown bit in COMMAND_REG to be cleared */

  while (mfrc522_readu8(dev, MFRC522_COMMAND_REG) & MFRC522_POWER_DOWN);
}

/****************************************************************************
 * Name: mfrc522_enableantenna
 *
 * Description:
 *   Turns the antenna on by enabling the pins TX1 and TX2
 *
 * Input Parameters: a pointer to mfrc522_dev_s structure
 *
 * Returned Value: none
 *
 ****************************************************************************/

void mfrc522_enableantenna(FAR struct mfrc522_dev_s *dev)
{
  uint8_t value = mfrc522_readu8(dev, MFRC522_TX_CTRL_REG);

  if ((value & (MFRC522_TX1_RF_EN | MFRC522_TX2_RF_EN)) != 0x03)
    {
      mfrc522_writeu8(dev, MFRC522_TX_CTRL_REG, value | 0x03);
    }
}

/****************************************************************************
 * Name: mfrc522_disableantenna
 *
 * Description:
 *   Turns the antenna off cutting the signals on TX1 and TX2
 *
 * Input Parameters: a pointer to mfrc522_dev_s structure
 *
 * Returned Value: none
 *
 ****************************************************************************/

void mfrc522_disableantenna(FAR struct mfrc522_dev_s *dev)
{
  uint8_t value = mfrc522_readu8(dev, MFRC522_TX_CTRL_REG);

  value &= ~(MFRC522_TX1_RF_EN | MFRC522_TX2_RF_EN);
  mfrc522_writeu8(dev, MFRC522_TX_CTRL_REG, value);
}

/****************************************************************************
 * Name: mfrc522_getfwversion
 *
 * Description:
 *   Read the MFRC522 firmware version.
 *
 * Input Parameters: a pointer to mfrc522_dev_s structure
 *
 * Returned Value: the firmware version byte
 *
 ****************************************************************************/

uint8_t mfrc522_getfwversion(FAR struct mfrc522_dev_s *dev)
{
  return mfrc522_readu8(dev, MFRC522_VERSION_REG);
}

/****************************************************************************
 * Name: mfrc522_getantennagain
 *
 * Description:
 *   Read the MFRC522 receiver gain (RxGain).
 * See 9.3.3.6 / table 98 in MFRC522 datasheet.
 *
 * Input Parameters: a pointer to mfrc522_dev_s structure
 *
 * Returned Value: none
 *
 ****************************************************************************/

uint8_t mfrc522_getantennagain(FAR struct mfrc522_dev_s *dev)
{
  return mfrc522_readu8(dev, MFRC522_RF_CFG_REG) & MFRC522_RX_GAIN_MASK;
}

/****************************************************************************
 * Name: mfrc522_setantennagain
 *
 * Description:
 *   Set the MFRC522 receiver gain (RxGain) to value value specified in mask.
 * See 9.3.3.6 / table 98 in MFRC522 datasheet.
 *
 * Input Parameters: a pointer to mfrc522_dev_s structure
 *
 * Returned Value: none
 *
 ****************************************************************************/

void mfrc522_setantennagain(FAR struct mfrc522_dev_s *dev, uint8_t mask)
{
  uint8_t value;

  if ((value = mfrc522_getantennagain(dev)) != mask)
    {
      mfrc522_writeu8(dev, MFRC522_RF_CFG_REG, value & ~MFRC522_RX_GAIN_MASK);
      mfrc522_writeu8(dev, MFRC522_RF_CFG_REG, mask & MFRC522_RX_GAIN_MASK);
    }
}

/****************************************************************************
 * Name: mfrc522_init
 *
 * Description:
 *   Initializes the MFRC522 chip
 *
 * Input Parameters: a pointer to mfrc522_dev_s structure
 *
 * Returned Value: none
 *
 ****************************************************************************/

void mfrc522_init(FAR struct mfrc522_dev_s *dev)
{
  /* Force a reset */

  mfrc522_softreset(dev);

  /* We need a timeout if something when communicating with a TAG case
   * something goes wrong. f_timer = 13.56 MHz / (2*TPreScaler+1) where:
   * TPreScaler = [TPrescaler_Hi:Tprescaler_Lo]. Tprescaler_Hi are the four
   * low bits in TmodeReg. Tprescaler_Lo is on TPrescalerReg.
   *
   * TAuto=1; timer starts automatically at the end of the transmission in
   * all communication modes at all speeds.
   */

  mfrc522_writeu8(dev, MFRC522_TMODE_REG, MFRC522_TAUTO);

  /* TPreScaler = TModeReg[3..0]:TPrescalerReg, ie: 0x0A9 = 169 =>
   * f_timer=40kHz, then the timer period will be 25us.
   */

  mfrc522_writeu8(dev, MFRC522_TPRESCALER_REG, 0xA9);

  /* Reload timer with 0x3E8 = 1000, ie 25ms before timeout. */

  mfrc522_writeu8(dev, MFRC522_TRELOAD_REGH, 0x06);
  mfrc522_writeu8(dev, MFRC522_TRELOAD_REGL, 0xE8);

  /* Force 100% ASK modulation independent of the ModGsPReg setting */

  mfrc522_writeu8(dev, MFRC522_TX_ASK_REG, MFRC522_FORCE_100ASK);

  /* Set the preset value for the CRC to 0x6363 (ISO 14443-3 part 6.2.4) */

  mfrc522_writeu8(dev, MFRC522_MODE_REG, 0x3D);

  /* Enable the Antenna pins */

  mfrc522_enableantenna(dev);
}

/****************************************************************************
 * Name: mfrc522_selftest
 *
 * Description:
 *   Executes a self-test of the MFRC522 chip
 *
 * See 16.1.1 in the MFRC522 datasheet
 *
 * Input Parameters: a pointer to mfrc522_dev_s structure
 *
 * Returned Value: none
 *
 ****************************************************************************/

int mfrc522_selftest(FAR struct mfrc522_dev_s *dev)
{
  uint8_t zeros[25] = {0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0};
  char outbuf[3 * 8 + 1];
  uint8_t result[64];
  int i;
  int j;
  int k;

  /* Execute a software reset */

  mfrc522_softreset(dev);

  /* Flush the FIFO buffer */

  mfrc522_writeu8(dev, MFRC522_FIFO_LEVEL_REG, MFRC522_FLUSH_BUFFER);

  /* Clear the internal buffer by writing 25 bytes 0x00 */

  mfrc522_writeblk(dev, MFRC522_FIFO_DATA_REG, zeros, 25);

  /* Transfer to internal buffer */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, MFRC522_MEM_CMD);

  /* Enable self-test */

  mfrc522_writeu8(dev, MFRC522_AUTOTEST_REG, MFRC522_SELFTEST_EN);

  /* Write 0x00 to FIFO buffer */

  mfrc522_writeu8(dev, MFRC522_FIFO_DATA_REG, 0x00);

  /* Start self-test by issuing the CalcCRC command */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, MFRC522_CALC_CRC_CMD);

  /* Wait for self-test to complete */

  for (i = 0; i < 255; i++)
    {
      uint8_t n;

      n = mfrc522_readu8(dev, MFRC522_DIV_IRQ_REG);
      if (n & MFRC522_CRC_IRQ)
        {
          break;
        }
    }

  /* Stop calculating CRC for new content in the FIFO */

  mfrc522_writeu8(dev, MFRC522_COMMAND_REG, MFRC522_IDLE_CMD);

  /* Read out the 64 bytes result from the FIFO buffer */

  mfrc522_readblk(dev, MFRC522_FIFO_DATA_REG, result, 64, 0);

  /* Self-test done. Reset AutoTestReg register to normal operation */

  mfrc522_writeu8(dev, MFRC522_AUTOTEST_REG, 0x00);

  mfrc522info("Self Test Result:\n");

  for (i = 0; i < 64; i += 8)
    {
      for (j = 0, k = 0; j < 8; j++, k += 3)
        {
          (void)sprintf(&outbuf[k], " %02x", result[i + j]);
        }

      mfrc522info("  %02x:%s\n", i, outbuf);
    }

  mfrc522info("Done!\n");
  return OK;
}

//----VVV----
static int rd_cmd_i = -1;
static int* rd_cmd_pars = NULL;
//----AAA----

/****************************************************************************
 * Name: mfrc522_open
 *
 * Description:
 *   This function is called whenever the MFRC522 device is opened.
 *
 ****************************************************************************/

static int mfrc522_open(FAR struct file *filep)
{
  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;

  mfrc522_configspi(dev->spi);

  nxsig_usleep(10000);

  mfrc522_getfwversion(dev);

  dev->state = MFRC522_STATE_IDLE;

  rd_cmd_i = -1;
  
  return OK;
}

/****************************************************************************
 * Name: mfrc522_close
 *
 * Description:
 *   This routine is called when the MFRC522 device is closed.
 *
 ****************************************************************************/

static int mfrc522_close(FAR struct file *filep)
{
  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;

  dev->state = MFRC522_STATE_NOT_INIT;

  rd_cmd_i = -1;

  return OK;
}




//----VVV----
#define CMD_LEN_MAX  32


typedef int (*parser_cb)(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]);


typedef struct {
  char* name;
  int  def_val;
} parser_param;


typedef struct {
  char* name;

  parser_cb cb;
  
  int par_cnt;
  const parser_param* par_lst;
} parser_cmd;


int read_uid(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]);
int read_dump(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]);

int write_uid(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]);
int write_dump(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]);


static parser_cmd commands_read[] = {
  {"Ruid", read_uid, 0, NULL},
  {"Rdump", read_dump, 0, NULL},
  {NULL, NULL, 0, NULL},
};


static parser_cmd commands_write[] = {
  {"Wuid", write_uid, 0, NULL},
  {"Wdump", write_dump, 0, NULL},
  {NULL, NULL, 0, NULL},
};


void dump_byte_array(uint8_t *buffer, uint8_t bufferSize) {
    for (uint8_t i = 0; i < bufferSize; i++) {
        DBG(" %2X", buffer[i]);
    }
}

void dump_byte_array1(uint8_t *buffer, uint8_t bufferSize) {
  for (uint8_t i = 0; i < bufferSize; i++) {
    DBG(buffer[i] < 0x10 ? " 0" : " ");
    DBG("%c", buffer[i]);
  }
}


MIFARE_Key key;

uint8_t buffer[18];
uint8_t block;
uint8_t waarde[64][16];
uint8_t status;


// Number of known default keys (hard-coded)
// NOTE: Synchronize the NR_KNOWN_KEYS define with the defaultKeys[] array
#define NR_KNOWN_KEYS   8
// Known keys, see: https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys
uint8_t knownKeys[NR_KNOWN_KEYS][MF_KEY_SIZE] =  {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF = factory default
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // 00 00 00 00 00 00
};


/*
 * Try using the PICC (the tag/card) with the given key to access block 0 to 63.
 * On success, it will show the key details, and dump the block data on Serial.
 *
 * @return true when the given key worked, false otherwise.
 */
 
bool try_key(FAR struct mfrc522_dev_s *dev, MIFARE_Key *key,
          FAR struct picc_uid_s* uid, FAR char *out_buffer, size_t buflen)
{
    int result = 0;
    int status;
    uint8_t buffer[18];

    for(uint8_t block = 0; block < 64; block++){
      
    // Serial.println(F("Authenticating using key A..."));
    status = PCD_Authenticate(dev, PICC_CMD_MF_AUTH_KEY_A, block, key, uid);
    if (status != OK) {
        DBG("PCD_Authenticate() failed: %s\n", GetStatusCodeName(dev, status));
        return 0;
    }

    // Read block
    uint8_t byteCount = sizeof(buffer);
    status = MIFARE_Read(dev, block, buffer, &byteCount);
    if (status != OK) {
        DBG("MIFARE_Read() failed: %s\n", GetStatusCodeName(dev, status));
    }
    else {
        // Successful read
        //result = true;
        DBG("Success with key:");
        dump_byte_array(key->keyByte, MF_KEY_SIZE);
        DBG("\n");
        
        // Dump block data
        DBG("Block %d:", block);
        dump_byte_array1(buffer, 16); //omzetten van hex naar ASCI
        DBG("\n");
        
        for (int p = 0; p < 16; p++) //De 16 bits uit de block uitlezen
        {
          int i = block*16 + p;
          if(i >= buflen)
            return buflen;

          out_buffer[i] = buffer[p];
          waarde [block][p] = buffer[p];
          DBG("%d ", waarde[block][p]);
        }
        
        }
    }
    DBG("\n");

    PICC_HaltA(dev);       // Halt PICC
    PCD_StopCrypto1(dev);  // Stop encryption on PCD
    return result;
}





int read_uid(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]){
  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;
  FAR struct picc_uid_s uid;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;

  /* Is a card near? */
  TRC("%s:%d\n", __func__, __LINE__);

  if (!mfrc522_picc_detect(dev))
    {
    TRC("%s:%d\n", __func__, __LINE__);
      mfrc522err("Card is not present!\n");
      return -EAGAIN;
    }
  TRC("%s:%d\n", __func__, __LINE__);
  mfrc522_picc_select(dev, &uid, 0);

  DBG("%s:%d sak=%d, uid.size=%d, buflen=%d\n", __func__, __LINE__, uid.sak, uid.size, buflen);
  if (uid.sak != 0)
    {
    TRC("%s:%d\n", __func__, __LINE__);
      if (buffer && buflen >= 3)
        {
          int i, j;
          TRC("%s:%d\n", __func__, __LINE__);
          snprintf(buffer, buflen, "0x");

          TRC("%s:%d\n", __func__, __LINE__);
          for(i = 0, j = 2; i < uid.size && j+2+1 <= buflen; i++, j += 2)
            {
              snprintf(&buffer[j], buflen-j, "%02X", uid.uid_data[i]);
            }
          PICC_HaltA(dev);       // Halt PICC
          PCD_StopCrypto1(dev);  // Stop encryption on PCD
          
          return buflen;
        }
    }
  return OK;
}


int read_dump(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]){
  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;
  FAR struct picc_uid_s uid;

  int ret = OK;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;

  /* Is a card near? */

  TRC("%s:%d\n", __func__, __LINE__);
  if (!mfrc522_picc_detect(dev))
    {
      TRC("%s:%d\n", __func__, __LINE__);
      mfrc522err("Card is not present!\n");
      return -EAGAIN;
    }

  TRC("%s:%d\n", __func__, __LINE__);
  mfrc522_picc_select(dev, &uid, 0);

  TRC("%s:%d\n", __func__, __LINE__);
  /* Try the known default keys */
  MIFARE_Key key;
  for (uint8_t k = 0; k < NR_KNOWN_KEYS; k++) {
      // Copy the known key into the MIFARE_Key structure
      for (uint8_t i = 0; i < MF_KEY_SIZE; i++) {
          key.keyByte[i] = knownKeys[k][i];
        }
TRC("%s:%d\n", __func__, __LINE__);
      // Try the key
      TRC("%s:%d\n", __func__, __LINE__);
      if (ret = try_key(dev, &key, &uid, buffer, buflen)) {
          TRC("%s:%d\n", __func__, __LINE__);
          // Found and reported on the key and block,
          // no need to try other keys for this PICC
         PICC_HaltA(dev);       // Halt PICC
         PCD_StopCrypto1(dev);  // Stop encryption on PCD
      
          return ret;
        }
    }
  
  return OK;
}


int write_uid(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]){
  int i, j;

  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;
  FAR struct picc_uid_s uid;

  uint8_t validbits = 0;

  int ret = OK;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;

  TRC("%s:%d bf=%x, ln=%d (%2x)\n", __func__, __LINE__, buffer, buflen, buffer[buflen-1]);
  if(buffer == NULL || buflen < 4*2 + 1 || buflen % 2 == 0 /*|| buffer[buflen-1] != '\0'*/)
    return -EIO;

  TRC("%s:%d\n", __func__, __LINE__);
  if(buffer[0] == '0' && (buffer[1] == 'x' || buffer[1] == 'X'))
    i = 2;
  else
    i = 0;
  
  TRC("%s:%d\n", __func__, __LINE__);
  memset(uid.uid_data, 0, 10);

  /* convert UID string to UID binary */

  TRC("%s:%d\n", __func__, __LINE__);
  for(j = 0; j < 10 && i < buflen-2 && isxdigit(buffer[i]); i+=2, j++)
    {
      char s[3];
      s[0] = buffer[i];
      s[1] = buffer[i+1];
      s[2] = '\0';
  
      uid.uid_data[j] = strtoul(s, NULL, 16);

      printf("d[%d] = %2X, ", j, uid.uid_data[j]);
  
      validbits += 8;
      }
  TRC("%s:%d\n", __func__, __LINE__);
  printf("validbits = %d\n", validbits);

  PICC_HaltA(dev);       // Halt PICC
  PCD_StopCrypto1(dev);  // Stop encryption on PCD

  /* Is a card near? */
  
  TRC("%s:%d\n", __func__, __LINE__);
  if (!mfrc522_picc_detect(dev))
    {
      mfrc522err("Card is not present!\n");
      return -EAGAIN;
    }

  /* Now write the UID */

  TRC("%s:%d\n", __func__, __LINE__);
  ret = mfrc522_picc_select(dev, &uid, validbits);
  DBG("ret = %d\n", ret);

  PICC_HaltA(dev);       // Halt PICC
  PCD_StopCrypto1(dev);  // Stop encryption on PCD

  return ret; //mfrc522_picc_select(dev, &uid, validbits);

/*
  if (uid.sak != 0)
    {
      if (buffer && buflen >= 3)
        {
          int i, j;
          snprintf(buffer, buflen, "0x");

          for(i = 0, j = 2; i < uid.size && j+2+1 <= buflen; i++, j += 2)
            {
              snprintf(&buffer[j], buflen-j, "%02X", uid.uid_data[i]);
            }
          return buflen;
        }
    }
*/
}


int write_dump(FAR struct file *filep, FAR char *buffer, size_t buflen, int pars[]){
  int i, j;

  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;
  FAR struct picc_uid_s uid;

  uint8_t validbits = 0;

  uint8_t block;
  uint8_t status;

  MIFARE_Key key;

  int ret = OK;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;

  DBG("Insert new card...");
  
  TRC("%s:%d\n", __func__, __LINE__);
  // Look for new cards
  if (!mfrc522_picc_detect(dev))
    {
      mfrc522err("Card is not present!\n");
      return -EAGAIN;
    }
  
  TRC("%s:%d\n", __func__, __LINE__);
  // Select one of the cards
  if ( !mfrc522_picc_select(dev, &uid, validbits))
    {
      mfrc522err("Card is not present!\n");
      return -EAGAIN;
    }

  TRC("%s:%d\n", __func__, __LINE__);
  // Show some details of the PICC (that is: the tag/card)
  DBG("Card UID:");
  dump_byte_array(uid.uid_data, uid.size);
  DBG("\n");

  uint8_t piccType = PICC_GetType(dev, uid.sak);
  DBG("PICC type: %s\n", PICC_GetTypeName(dev, piccType));

  // Try the known default keys
/*
  MFRC522::MIFARE_Key key;
  for (byte k = 0; k < NR_KNOWN_KEYS; k++) {
      // Copy the known key into the MIFARE_Key structure
      for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
          key.keyByte[i] = knownKeys[k][i];
      }
  }
*/
  for (uint8_t i = 0; i < 6; i++) {
      key.keyByte[i] = 0xFF;
  }

  TRC("%s:%d\n", __func__, __LINE__);
  for(int i = 4; i <= 62; i++){ //De blocken 4 tot 62 kopieren, behalve al deze onderstaande blocken (omdat deze de authenticatie blokken zijn)
    if(i == 7 || i == 11 || i == 15 || i == 19 || i == 23 || i == 27 || i == 31 || i == 35 || i == 39 || i == 43 || i == 47 || i == 51 || i == 55 || i == 59){
      i++;
    }
    block = i;

  TRC("%s:%d\n", __func__, __LINE__);
  // Authenticate using key A
  DBG("Authenticating using key A...\n");
  status = PCD_Authenticate(dev, PICC_CMD_MF_AUTH_KEY_A, block, &key, &uid);
  if (status != OK) {
    DBG("PCD_Authenticate() failed: %s\n", GetStatusCodeName(dev, status));
    return -EIO;
  }

  TRC("%s:%d\n", __func__, __LINE__);
  // Authenticate using key B
  DBG("Authenticating again using key B...\n");
  status = PCD_Authenticate(dev, PICC_CMD_MF_AUTH_KEY_B, block, &key, &uid);
  if (status != OK) {
    DBG("PCD_Authenticate() failed: %s\n", GetStatusCodeName(dev, status));
    return -EIO;
  }

  // Write data to the block
  DBG("Writing data into block %d\n", block);
 
  dump_byte_array(waarde[block], 16); 
 
  TRC("%s:%d\n", __func__, __LINE__);
  status = MIFARE_Write(dev, block, waarde[block], 16);
  if (status != OK) {
    DBG("MIFARE_Write() failed: %s\n", GetStatusCodeName(dev, status));
  }
  TRC("%s:%d\n", __func__, __LINE__);

  DBG("\n\n");

  }
  PICC_HaltA(dev);       // Halt PICC
  PCD_StopCrypto1(dev);  // Stop encryption on PCD
}



static void help(){
  int i;

  printf("\nHelp:\n");
  printf("\nRead commands:\n");
  for(i = 0; commands_read[i].name != NULL; i++){
    if(commands_read[i].cb != NULL)
      printf("%s:..\n", commands_read[i].name);
    }

  printf("\nWrite commands:\n");
  for(i = 0; commands_write[i].name != NULL; i++){
    if(commands_write[i].cb != NULL)
      printf("%s:..\n", commands_write[i].name);
    }
}




//----AAA----

/****************************************************************************
 * Name: mfrc522_read
 *
 * Description:
 *   This routine is called when the device is read.
 *
 * Returns TAG id as string to buffer.
 * or -EIO if no TAG found
 *
 ****************************************************************************/

static ssize_t mfrc522_read(FAR struct file *filep, FAR char *buffer,
    size_t buflen)
{
#if 0
  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;
  //FAR struct picc_uid_s uid;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;

  /* Is a card near? */

  if (!mfrc522_picc_detect(dev))
    {
      mfrc522err("Card is not present!\n");
      return -EAGAIN;
    }
#endif

  TRC("%s:%d\n", __func__, __LINE__);
  if(rd_cmd_i >= 0){
    TRC("%s:%d\n", __func__, __LINE__);
    return commands_read[rd_cmd_i].cb(filep, buffer, buflen, NULL);
    }

  help();

#if 0
  /* Now read the UID */

  mfrc522_picc_select(dev, &uid, 0);

  if (uid.sak != 0)
    {
      if (buffer && buflen >= 3)
        {
          int i, j;
          snprintf(buffer, buflen, "0x");

          for(i = 0, j = 2; i < uid.size && j+2+1 <= buflen; i++, j += 2)
            {
              snprintf(&buffer[j], buflen-j, "%02X", uid.uid_data[i]);
            }


          //----VVV----
              for (uint8_t i = 0; i < 6; i++) {
                  key.keyByte[i] = 0xFF;
              }
          
              printf("\n\nRead the card:\n");
              printf("1>-------------------------------------------\n");
              keuze1(dev);
              
              printf("\n\nSee what is in the variables:\n");
              printf("2>-------------------------------------------\n");
              keuze2();
          
              printf("\n\nWrite the card:\n");
              printf("3>-------------------------------------------\n");
              //keuze3(dev);
              
              for (uint8_t i = 0; i < 6; i++) {
                key.keyByte[i] = 0xFF;
              }
              
                // Dump UID
                printf("Card UID:");
                for (uint8_t i = 0; i < uid.size; i++) {
                  printf(" %2X", uid.uid_data[i]);
                } 
                printf("\n");
              
                // Dump PICC type
                uint8_t piccType = PICC_GetType(dev, uid.sak);
                
                printf("PICC type: %s (SAK %d)\n", PICC_GetTypeName(dev, piccType), uid.sak);
                if (  piccType != PICC_TYPE_MIFARE_MINI 
                  &&  piccType != PICC_TYPE_MIFARE_1K
                  &&  piccType != PICC_TYPE_MIFARE_4K) {
                  printf("This sample only works with MIFARE Classic cards.\n");
                  return buflen;
                }



                  // Set new UID
                  uint8_t newUid[] = NEW_UID;
                  if ( MIFARE_SetUid(dev, newUid, (uint8_t)4, true) ) {
                    printf("Wrote new UID to card.\n");
                  }
                  
                  // Halt PICC and re-select it so DumpToSerial doesn't get confused
                  PICC_HaltA(dev);
                  if ( ! mfrc522_picc_detect(dev) || ! PICC_ReadCardSerial(dev) ) {
                    return buflen;
                  }
                  
                  // Dump the new memory contents
                  printf("New UID and contents:\n");
                  PICC_DumpToSerial(dev, &uid);

          //----AAA----


          return buflen;
        }
    }
#endif
  return OK;
}


/****************************************************************************
 * Name: mfrc522_write
 ****************************************************************************/

static ssize_t mfrc522_write(FAR struct file *filep, FAR const char *buffer,
     size_t buflen)
{
  int j, i, idat=-1, ipar=-1;
  char rd_cmd[CMD_LEN_MAX+1];
#if 0
  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;
  FAR struct picc_uid_s uid;

//  uint8_t validbits = 0;
//  uint8_t i, j;

TRC("%s:%d\n", __func__, __LINE__);

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  TRC("%s:%d\n", __func__, __LINE__);
  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;
#endif

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
      return -EIO;
    }

  TRC("%s:%d\n", __func__, __LINE__);
  for(i = 0; commands_read[i].name != NULL; i++){
    if(!strcmp(commands_read[i].name, rd_cmd)){
      if(commands_read[i].cb != NULL)
        TRC("%s:%d\n", __func__, __LINE__);
        rd_cmd_i = i;
        return buflen;
      }
    }

  TRC("%s:%d\n", __func__, __LINE__);
  for(i = 0; commands_write[i].name != NULL; i++){
    if(!strcmp(commands_write[i].name, rd_cmd)){
      if(commands_write[i].cb != NULL)
        return commands_write[i].cb(filep, &buffer[idat], buflen - idat, NULL);
      }
    }
  TRC("%s:%d\n", __func__, __LINE__);

  help();

  return OK;
}

/****************************************************************************
 * Name: mfrc522_ioctl
 ****************************************************************************/

static int mfrc522_ioctl(FAR struct file *filep, int cmd, unsigned long arg)
{
  FAR struct inode *inode;
  FAR struct mfrc522_dev_s *dev;
  int ret = OK;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = inode->i_private;

  switch (cmd)
    {
    case MFRC522IOC_GET_PICC_UID:
      {
        struct picc_uid_s *uid = (struct picc_uid_s *)arg;

        /* Is a card near? */

        if (mfrc522_picc_detect(dev))
          {
            ret = mfrc522_picc_select(dev, uid, 0);
          }
      }
      break;

    case MFRC522IOC_GET_STATE:
      ret = dev->state;
      break;

    default:
      mfrc522err("ERROR: Unrecognized cmd: %d\n", cmd);
      ret = -ENOTTY;
      break;
    }

  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: mfrc522_register
 *
 * Description:
 *   Register the MFRC522 character device as 'devpath'
 *
 * Input Parameters:
 *   devpath - The full path to the driver to register.
 *             E.g., "/dev/rfid0"
 *   spi     - An instance of the SPI interface to use to communicate with
 *             MFRC522.
 *   config  - chip config
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value on failure.
 *
 ****************************************************************************/

int mfrc522_register(FAR const char *devpath, FAR struct spi_dev_s *spi)
{
  FAR struct mfrc522_dev_s *dev;
  uint8_t fwver;
  int ret = 0;

  /* Initialize the MFRC522 device structure */

  dev = (FAR struct mfrc522_dev_s *)kmm_malloc(sizeof(struct mfrc522_dev_s));
  if (!dev)
    {
      mfrc522err("ERROR: Failed to allocate instance\n");
      return -ENOMEM;
    }

  dev->spi = spi;

  /* Device is not initialized yet */

  dev->state = MFRC522_STATE_NOT_INIT;

#if defined CONFIG_PM
  dev->pm_level = PM_IDLE;
#endif

  /* mfrc522_attachirq(dev, mfrc522_irqhandler); */

  /* Initialize the MFRC522 */

  mfrc522_init(dev);

  /* Device initialized and idle */

  dev->state = MFRC522_STATE_IDLE;

  /* Read the Firmware Version */

  fwver = mfrc522_getfwversion(dev);

  mfrc522info("MFRC522 Firmware Version: 0x%02X!\n", fwver);
  printf("MFRC522 Firmware Version: 0x%02X!\n", fwver);

  /* If returned firmware version is unknown don't register the device */

  if (fwver != 0x90 && fwver != 0x91 && fwver != 0x92 && fwver != 0x88 )
    {
      mfrc522err("None supported device detected!\n");
      //goto firmware_error;
    }

  /* Register the character driver */

  ret = register_driver(devpath, &g_mfrc522fops, 0666, dev);
  if (ret < 0)
    {
      mfrc522err("ERROR: Failed to register driver: %d\n", ret);
      kmm_free(dev);
    }

  return ret;

firmware_error:
  kmm_free(dev);
  return -ENODEV;
}
