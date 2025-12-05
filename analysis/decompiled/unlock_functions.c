================================================================================
Ghidra Function Decompilation - libmal_qct.so
================================================================================


--------------------------------------------------------------------------------
Function: modem2_modem_carrier_unlock
Address: 00039f4c
--------------------------------------------------------------------------------


undefined4 modem2_modem_carrier_unlock(char *param_1)

{
  undefined4 uVar1;
  int iVar2;
  char acStack_78 [107];
  undefined1 local_d;
  int local_c;
  
  local_c = 0;
  if (*(int *)(DAT_0003a1fc + 0x39f70) == 1) {
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_0003a214 + 0x39ff8,5,DAT_0003a218 + 0x3a008,DAT_0003a21c + 0x3a014,uVar1,
                 DAT_0003a210 + 0x39fe4,param_1);
    local_d = 0;
    memset(acStack_78,0,0x68);
    local_c = nwqmi_nvtl_nv_item_read_cmd(0xea64,acStack_78,0x68);
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_0003a224 + 0x3a078,5,DAT_0003a228 + 0x3a088,DAT_0003a22c + 0x3a094,uVar1,
                 DAT_0003a220 + 0x3a064,local_c);
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_0003a234 + 0x3a0c4,5,DAT_0003a238 + 0x3a0d4,DAT_0003a23c + 0x3a0e0,uVar1,
                 DAT_0003a230 + 0x3a0b0,acStack_78);
    iVar2 = strncmp(acStack_78,param_1,0x68);
    if (iVar2 == 0) {
      local_c = nwqmi_nvtl_nv_item_write_cmd(0xeaac,&local_d,1);
      uVar1 = mifi_dbg_get_level_name(5);
      mifi_dbg_log(DAT_0003a244 + 0x3a148,5,DAT_0003a248 + 0x3a158,DAT_0003a24c + 0x3a164,uVar1,
                   DAT_0003a240 + 0x3a134,local_c);
      if (local_c == 0) {
        local_c = nwqmi_nvtl_nv_item_write_cmd(0xea62,&local_d,1);
        uVar1 = mifi_dbg_get_level_name(5);
        mifi_dbg_log(DAT_0003a254 + 0x3a1b8,5,DAT_0003a258 + 0x3a1c8,DAT_0003a25c + 0x3a1d4,uVar1,
                     DAT_0003a250 + 0x3a1a4,local_c);
      }
      if (local_c == 0) {
        return 0xc0000;
      }
    }
  }
  else {
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_0003a204 + 0x39fa0,5,DAT_0003a208 + 0x39fb0,DAT_0003a20c + 0x39fbc,uVar1,
                 DAT_0003a200 + 0x39f94);
  }
  return 0xc0001;
}



--------------------------------------------------------------------------------
Function: modem2_modem_get_carrier_unlock_status
Address: 00039d80
--------------------------------------------------------------------------------


undefined4 modem2_modem_get_carrier_unlock_status(undefined4 *param_1)

{
  undefined4 uVar1;
  char local_d;
  int local_c;
  
  local_c = 0;
  if (*(int *)(DAT_00039f28 + 0x39da4) == 1) {
    uVar1 = mifi_dbg_get_level_name(7);
    mifi_dbg_log(DAT_00039f40 + 0x39e24,7,DAT_00039f44 + 0x39e34,DAT_00039f48 + 0x39e40,uVar1,
                 DAT_00039f3c + 0x39e18);
    local_d = '\0';
    local_c = nwqmi_nvtl_nv_item_read_cmd(0xeaac,&local_d,1);
    if ((local_c == 0) && (local_d == '\0')) {
      local_c = nwqmi_nvtl_nv_item_read_cmd(0xea62,&local_d,1);
    }
    if (local_c == 0) {
      if (local_d == '\0') {
        *param_1 = 0;
        param_1[1] = 10;
        param_1[2] = 0;
        param_1[3] = 0;
      }
      else {
        *param_1 = 1;
        param_1[1] = 10;
        param_1[2] = 0;
        param_1[3] = 0;
      }
      uVar1 = 0xc0000;
    }
    else {
      uVar1 = 0xc0001;
    }
  }
  else {
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_00039f30 + 0x39dd4,5,DAT_00039f34 + 0x39de4,DAT_00039f38 + 0x39df0,uVar1,
                 DAT_00039f2c + 0x39dc8);
    uVar1 = 0xc0001;
  }
  return uVar1;
}



--------------------------------------------------------------------------------
Function: modem2_modem_validate_spc
Address: 00037964
--------------------------------------------------------------------------------


undefined4 modem2_modem_validate_spc(undefined4 param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 local_c;
  
  local_c = 0xc0001;
  if (*(int *)(DAT_00037a88 + 0x37994) == 1) {
    iVar2 = nwqmi_dms_validate_spc(param_1);
    if (iVar2 == 0) {
      local_c = 0xc0000;
    }
    else if (iVar2 == 0x22) {
      local_c = 0xc03e9;
    }
    else {
      uVar1 = mifi_dbg_get_level_name(3);
      mifi_dbg_log(DAT_00037aa0 + 0x37a5c,3,DAT_00037aa4 + 0x37a6c,DAT_00037aa8 + 0x37a78,uVar1,
                   DAT_00037a9c + 0x37a48,iVar2);
    }
  }
  else {
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_00037a90 + 0x379c4,5,DAT_00037a94 + 0x379d4,DAT_00037a98 + 0x379e0,uVar1,
                 DAT_00037a8c + 0x379b8);
    local_c = 0xc0001;
  }
  return local_c;
}



--------------------------------------------------------------------------------
Function: modem2_modem_get_spc_validate_limit
Address: 0003788c
--------------------------------------------------------------------------------


undefined4 modem2_modem_get_spc_validate_limit(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 local_c;
  
  local_c = 0xc0001;
  if (*(int *)(DAT_00037950 + 0x378b4) == 1) {
    if (param_1 == 0) {
      local_c = 0xc0002;
    }
    else {
      iVar2 = nwqmi_nvtl_read_otksk_counter(param_1);
      if (iVar2 == 0) {
        local_c = 0xc0000;
      }
    }
  }
  else {
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_00037958 + 0x378e4,5,DAT_0003795c + 0x378f4,DAT_00037960 + 0x37900,uVar1,
                 DAT_00037954 + 0x378d8);
    local_c = 0xc0001;
  }
  return local_c;
}



--------------------------------------------------------------------------------
Function: nwqmi_dms_validate_spc
Address: EXTERNAL:00000073
--------------------------------------------------------------------------------

// Decompilation failed

--------------------------------------------------------------------------------
Function: dsm_modem_get_imei
Address: 00042b84
--------------------------------------------------------------------------------


undefined4 dsm_modem_get_imei(void *param_1,uint param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined1 auStack_58 [80];
  
  memset(auStack_58,0,0x50);
  iVar1 = nwqmi_nvtl_nv_item_read_cmd(0x226,auStack_58,0x50);
  if (iVar1 == 0) {
    if (param_2 < 0x50) {
      memcpy(param_1,auStack_58,4);
    }
    else {
      memcpy(param_1,auStack_58,0x50);
    }
    uVar2 = 0;
  }
  else {
    uVar2 = mifi_dbg_get_level_name(3);
    mifi_dbg_syslog(0x8a,DAT_00042ca8 + 0x42bf4,DAT_00042cac + 0x42c00,uVar2,DAT_00042ca4 + 0x42be4)
    ;
    uVar2 = mifi_dbg_get_level_name(3);
    mifi_dbg_log(DAT_00042cb4 + 0x42c30,3,DAT_00042cb8 + 0x42c40,DAT_00042cbc + 0x42c4c,uVar2,
                 DAT_00042cb0 + 0x42c24);
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

