# Introduction
This write-up describes a buffer overflow vulnerability in v1.2.0 of the X-CUBE-SAFEA1 Software Package for STSAFE-A [sample applications](https://www.st.com/en/embedded-software/x-cube-safea1.html).
To be more specific, the vulnerable code is in v3.3.6 and below of the STSAFE-Axx middleware within the package.
We identified this bug during our investigations of the STSAFE-A110 secure element.

# Overview
The vulnerability exists in the `int StSafeA_ReceiveBytes(StSafeA_TLVBuffer_t *pOutBuffer)` function in the shared `stsafe_service.c` file. 
This function is called every time data is received on the I2C bus in all of the sample applications of the repository.
Because this is the only code base we could find that would serve as a reference implementation of STSAFE-A110 functionality, it is likely that developers would reuse parts of the code, making them vulnerable to any inherent bugs.
Therefore, we believe that even though users are responsible for the security and correctness of their own software, ST has a responsibility to provide secure sample and reference code. 

To exploit the bug, an attacker needs to be in a Person-in-the-Middle position on the I2C bus, between the MCU and the STSAFE-A110. 

The vulnerable function is shown in the following pseudocode:
```C
int8_t StSafeA_ReceiveBytes(StSafeA_TLVBuffer_t *pOutBuffer)

{
  int32_t statuscode;
  StSafeA_TLVBuffer_t *pOutBuffer-local;
  uint16_t response_length;
  uint16_t loop;
  int8_t status_code;
  ushort resp_length;
  
  resp_length = (pOutBuffer->LV).Length;
  status_code = STSAFE_BUS_ERR; 
  loop = 1;

  /* In order to avoid excess data sending over I2C */
  /* pInBuffer->LV.Length should not exceed the max allowed size */
  if (resp_length + 1 < STSAFEA_HEADER_LENGTH) {

    /* To optimize stack size and avoid to allocate memory for a dedicated receive
       buffer, the pOutBuffer.Data is used to receive over the Bus. Than the
       pOutBuffer structure is re-adjusted in the proper way */     
    if ((pOutBuffer->LV).Data != (uint8_t *)0x0) {
    
      for (; (status_code != STSAFEA_BUS_OK && (loop < (STSAFEA_I2C_POLLING_MAX / STSAFEA_I2C_POLLING_STEP))); loop = loop + STSAFEA_I2C_POLLING_STEP) { // 
        statuscode = (*HwCtx.BusRecv)((uint16_t)((HwCtx.DevAddr & 0x7fff) << 1),
                                      (pOutBuffer->LV).Data,resp_length + 3);
        status_code = (int8_t)statuscode;
        if (status_code == STSAFEA_BUS_NACK) {
          (*HwCtx.TimeDelay)(STSAFEA_I2C_POLLING_STEP); // 
        }
      }

      /* At this point the pOutBuffer.Header, Length, Data is re-adjusted in the proper way*/
      pOutBuffer->Header = *(pOutBuffer->LV).Data;
      (pOutBuffer->LV).Length =
           (ushort)(pOutBuffer->LV).Data[2] + (ushort)(pOutBuffer->LV).Data[1] * 0x100;
      memcpy((pOutBuffer->LV).Data,(pOutBuffer->LV).Data + 3,(uint)resp_length);

      /* If STSAFE returns a length higher than expected, a new read with the
      updated bytes length is executed */
      if ((resp_length < (pOutBuffer->LV).Length) && (status_code == '\0')) {
        status_code = -1;
        for (loop = 1; (status_code != STSAFEA_BUS_OK && (loop < (STSAFEA_I2C_POLLING_MAX / STSAFEA_I2C_POLLING_STEP))); loop = loop + STSAFEA_I2C_POLLING_STEP) {
          statuscode = (*HwCtx.BusRecv)((uint16_t)((HwCtx.DevAddr & 0x7fff) << 1),
                                        (pOutBuffer->LV).Data,(pOutBuffer->LV).Length + 3);
          status_code = (int8_t)statuscode;
          if (status_code == STSAFEA_BUS_NACK) {
            (*HwCtx.TimeDelay)(STSAFEA_I2C_POLLING_STEP);
          }
        }
        pOutBuffer->Header = *(pOutBuffer->LV).Data;
        (pOutBuffer->LV).Length =
             (ushort)(pOutBuffer->LV).Data[2] + (ushort)(pOutBuffer->LV).Data[1] * 0x100;
        memcpy((pOutBuffer->LV).Data,(pOutBuffer->LV).Data + 3,(uint)(pOutBuffer->LV).Length);
      }
    }
  }
  else {
    status_code = STSAFEA_BUFFER_LENGTH_EXCEEDED;
  }
  return status_code;
}
```
The vulnerability is in the second `HwCtx.BusRecv()` call. 

# The `InOutBuffer` 
Across the lifetime of the application one data structure is used to hold data both when sending to the STSAFE-A110 and when receiveing from it. 
Below is the definition of the structure:
```C
struct StSafeA_Handle_t {
    struct StSafeA_TLVBuffer_t InOutBuffer;
    uint8_t CrcSupport;
    uint8_t MacCounter;
    uint32_t HostMacSequenceCounter;
    struct StSafeA_Hash_t HashObj;
};
```

This data structure is initialised in `main.c`, where the `InOutBuffer` is initalised with a maximum size, which is the `a_rx_tx_stsafe_data`: 
```C
int main(void)
{
uint8_t a_rx_tx_stsafea_data [523];
[...]
    statuscode = StSafeA_Init(&stsafea_handle,a_rx_tx_stsafea_data);
[...]
```
This makes the maximum size of the buffer 523 bytes, but in user applications could be changed to be smaller. 

# Breakdown
The `StSafeA_ReceiveBytes()` function performs two reads from the I2C bus. After the first one, the data read is then copied into the `LV.Data` buffer as seen in the following pseudocode:
```C
// The  `response_length` is not user controlled at this point, but takes its 
// value from the `LV.Length` field set by a caller function to the expected
// response length.
uint16_t response_length;
uint16_t loop;
int8_t status_code;
ushort resp_length;

resp_length = (pOutBuffer->LV).Length;
status_code = STSAFE_BUS_ERR; 
loop = 1;

if (resp_length + 1 < STSAFEA_HEADER_LENGTH) {

  if ((pOutBuffer->LV).Data != (uint8_t *)0x0) {
  
    for (; (status_code != STSAFEA_BUS_OK && (loop < (STSAFEA_I2C_POLLING_MAX / STSAFEA_I2C_POLLING_STEP))); loop = loop + STSAFEA_I2C_POLLING_STEP) {

    // The MCU reads `resp_length + 3` bytes from the I2C bus
    // using its low level API
    statuscode = (*HwCtx.BusRecv)((uint16_t)((HwCtx.DevAddr & 0x7fff) << 1),
                                  (pOutBuffer->LV).Data,resp_length + 3);
    status_code = (int8_t)statuscode;
    if (status_code == STSAFEA_BUS_NACK) {
      (*HwCtx.TimeDelay)(STSAFEA_I2C_POLLING_STEP);
    }
  }
```

The issue surfaces when two bytes from the `LV.Data` field - which is the data directly read from the I2C bus -, is used to re-set the `LV.Length` field.
An attacker needs to send two bytes that contain a large integer value in the I2C message which place will correspond to the second and third bytes
of the `LV.Data` field in the `pOutBuffer`.
This size needs to be larger than the originally expected `response_length` which will be based on the STSAFE command being executed.
The size also needs to be larger than the maximum size of the buffer (see above), which is 523 bytes. 
Anything larger than this will be written beyond the `InOutBuffer`, overwriting other fields of the `StSafeA_Handle_t` structure and possibly beyond.
```C
// The Header is updated with the first byte of the response stream
pOutBuffer->Header = *(pOutBuffer->LV).Data;
// More importantly, the output buffer's data length is re-set based on the
// second and third bytes from the I2C message, without validation
(pOutBuffer->LV).Length = (ushort)(pOutBuffer->LV).Data[2] + (ushort)(pOutBuffer->LV).Data[1] * 0x100;
// The received data is copied into memory with an upper limit of the original length of the data.
// This is fine, because the size of the copied buffer is set by the non-attacker controlled `response_length` variable
memcpy((pOutBuffer->LV).Data,(pOutBuffer->LV).Data + 3,(uint)resp_length);
```

Following this, a check is made whether the attacker controlled message size is bigger than the expected response length.
```C
// The now attacker-controlled `LV.Length` - which was based on the user-controlled `LV.Data[1]
// and LV.Data[2] bytes - is now checked whether it's larger than the expected response length
if ((resp_length < (pOutBuffer->LV).Length) && (status_code == STSAFEA_BUS_OK)) {
```

If this is the case, then another read happens from the I2C bus, reading data to the size specified by the attacker above, and thus overflowing the `LV.Data` field in the `pOutBuffer` structure, leading to the vulnerability:
```C
status_code = -1;
for (loop = 1; (status_code != STSAFEA_BUS_OK && (loop < (STSAFEA_I2C_POLLING_MAX / STSAFEA_I2C_POLLING_STEP))); loop = loop + STSAFEA_I2C_POLLING_STEP) {
{
// Further data is read from the I2C bus, up to the now user-controlled length
statuscode = (*HwCtx.BusRecv)((uint16_t)((HwCtx.DevAddr & 0x7fff) << 1),
                                  (pOutBuffer->LV).Data,(pOutBuffer->LV).Length + 3);
    status_code = (int8_t)statuscode;
    if (status_code == STSAFEA_BUS_NACK) {
      (*HwCtx.TimeDelay)(STSAFEA_I2C_POLLING_STEP);
    }
  }
```

# Risk
As mentioned above, the attacker needs to be in a privileged position to be able to intercept I2C traffic, which means local access to the affected device.
Furthermore, because the vulnerability exists in the method that handles responses to STSAFE commands, the attacker needs to be able to send responses either by impersonating an STSAFE-A110 component, or injecting traffic into the I2C bus.

However, upon successful exploitation the attacker could achieve code execution on the MCU.

# Timeline

* July, 2023 - Vulnerability identified by Zoltan Madarassy, elttam
* 23 Aug, 2023 - Vulnerability reported to ST PSIRT
* 10 Oct, 2023 - Fixed version (v3.3.7) of the STSAFE-A1xx middleware published by ST
* 1 Dec, 2023 - Advisory published and CVE requested