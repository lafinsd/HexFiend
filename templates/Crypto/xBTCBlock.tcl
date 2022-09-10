# Bitcoin Core Block
#   Process a single Bitcoin block contained in a Bitcoin Core blk*.dat file. 
#


# Return a BTC varint value. Presence of an argument causes the varint to be displayed as a Hex Fiend 
# field with the argument as the label. The file pointer is left at the first byte past the varint field.
proc getVarint {args} {
  
    # Read the indicator byte
    set val [uint8]
    
    if {$val == 0xfd} {
      set val    [uint16]
      set type   "uint16"
      set moveit -2
    } elseif {$val == 0xfe} {
       set val    [uint32]
       set type   "uint32"
       set moveit -4
    } elseif {$val == 0xff} {
       set val    [uint64]
       set type   "uint64"
       set moveit -8
    } else {
       set moveit -1
       set type   "uint8"
    }
    
    if {[llength $args] == 1}  {
      move $moveit
      $type [lindex $args 0]
    }

    return $val
}

proc isPubKey {} {
  set klen [uint8]
  set op [uint8]
  move -2
  
  if {$klen != 0x21} {
    return 0
  }

  if {$op != 2 && $op != 3} {
    return 0
  }
  return 1
}

proc decodePubKey {len} {
  bytes $len "PubKey"
  return 1
}

proc decodeMultiSig {} {
  set OP_ [expr {[uint8] - 80} ]
  if {![isPubKey]} {
    move -1
    return 0
  }
  section -collapsed "m of n Multisig PubKeys" {
    move -1
    uint8 "m  (OP_$OP_)"
    set sigs 1
    while {$sigs} {
      set len [uint8]
      if {$len == 33} {
        decodePubKey $len
      } else {
        move -1
        set sigs 0
      }
    }
    
    set OP_ [expr {[uint8] - 80} ]
    move -1
    uint8 "n  (OP_$OP_)"
    
    set op [uint8]
    if {$op == 0xae} {
      set type "OP_CHECKMULTISIG"
    } elseif {$op == 0xaf} {
      set type "OP_CHECKMULTISIGVERIFY"
    } else {
      set type "OP_IDK"
    }
    move -1
    uint8 "$type" 
  }
  return 1
}

proc decodeSig {} {
  section -collapsed "Signature" {
    uint8 -hex "DER"
    uint8 "struct length"
    uint8 "integer marker"
    set r [uint8]
    move -1
    uint8 "r length"
    bytes $r "r"
    uint8 "integer marker"
    set s [uint8]
    move -1
    uint8 "s length"
    bytes $s "s"
    uint8 "SIGHASH flag"
  }
  return 1
}

proc isSignature {len}  {

  set curpos 0
  set DER [uint8]
  incr curpos
  if {$DER != 0x30} {
    move -$curpos
    return 0
  }
  
  set slen [uint8]
  incr curpos
  if {[expr {$slen + 3}] != $len} {
    move -$curpos
    return 0
  }
  
  for {set i 0} {$i < 2} {incr i} {
    set intmrk [uint8]
    incr curpos
    if {$intmrk != 2} {
      move -$curpos
      return 0
    }
  
    set pslen [uint8]
    incr curpos
    if {[expr {$pslen + $curpos}] > $len} {
      move -$curpos
      return 0
    }
  
    move $pslen
    incr curpos $pslen
  }
  
  set sighash [uint8]
  incr curpos
  move -$curpos
  
  if {$curpos != $len} {
    return 0
  }
  
  return 1
}

proc witnessType {len} {
  if {$len == 0} {
    set type "wtOP_0"
  } else {
    set op [uint8]
    move -1

    if {$op == 0x30 && $len >= 67 &&  $len <= 73} {
      set type "wtDER"
      set rv [isSignature $len]
      if {$rv == 0} {
        set type "wtbadDER"
      }
#      entry "isSig rv " $rv
    } elseif {$op >= 0x51 && $op <= 0x60 && $len != 32} {
      set type "wtOP_"
    } elseif {$len == 33 && ($op == 2  ||  $op == 3)} {
      set type "wtPK"
    } else {
      set type "wtIDK"
    }
  }
  return $type
}


proc isTarget {Target} {
  # target string
  entry "target" $Target
  
  set slen [string length $Target]
  entry "slen" $slen
  
  if {$slen % 2} {return 0}

 # Target literal string must be prefixed with "0x" because the Hex Fiend hex read will prefix read result with an 0x
 set strTarget "0x"
 append strTarget $Target
 entry "appended target" $strTarget
 
 # read the test data
  set strTest [hex [expr {$slen/2}]]
  entry "test" $strTest

  # here's the actual test
  if {$strTest == $strTarget} {
    set retval 1
  } else {
    set retval 0
  }

  entry "isTarget retval" $retval
  return $retval
}

proc getOP_CODE {string idx} {

if {1} {  
  set ncodes { \
          "00" \
          "4C" \
          "4D" \
          "4E" \
          "6A" \
          "76" \
          "88" \
          "87" \
          "A9" \
          "AC" \ 
          "AE" \   
       }
       
  set mcodes { \
          "OP_0" \
          "OP_PUSHDATA1" \
          "OP_PUSHDATA2" \
          "OP_PUSHDATA4" \
          "OP_RETURN" \
          "OP_DUP" \
          "OP_EQUALVERIFY" \
          "OP_EQUAL" \
          "OP_HASH160" \
          "OP_CHECKSIG" \    
          "OP_CHECKMULTISIG" \
       }
       
  set retval "OP_IDK"
  set auxval 0
  
  set opcode [string index $string $idx][string index $string [incr idx]]
  scan $opcode %x numericOC
 
  if {$numericOC > 0  &&  $numericOC < 76} {
    set retval "OP_PUSH"
    set auxval $numericOC
  } elseif {$numericOC > 80  &&  $numericOC < 97} {
    set retval "OP_[]"
    set auxval [expr {$numericOC - 80}]
  } else {
    set indx [lsearch $ncodes $opcode]
    if {$indx >= 0} {
      set retval [lindex $mcodes $indx]
    }
  }
  
  if {$retval == "OP_PUSHDATA1"} {
    incr idx 
    set opcode [string index $string $idx][string index $string [incr idx]]
    scan $opcode %x numericOC
    set auxval $numericOC
  }
  
  return [list $retval $auxval]
}
}

proc parseSPK {len script}  {
#  entry "slen" $len
#  entry "SPK" $script
  set pos [expr $len * 2 + 2]
if {1} {  
  for {set i 2} {$i < $pos} {incr i 2} {
    set opcode [getOP_CODE $script $i]
    entry "opcode" $opcode
    lassign $opcode cmd auxval
    if {$cmd == "OP_IDK"} {return 0}
    if {$cmd == "OP_PUSH"} {
      # skip over the bytes pushed
      incr i [expr $auxval*2]
    }
    if {$cmd == "OP_PUSHDATA1"} {
      # skip over the nyte count and the bytes pushed
      incr i [expr $auxval*2 + 2]
    }
  }
}
 return 1
}


# *********************************************************************************************************************


# BTC Magic is 4 bytes (0xF9BEB4D9) but it is more convenient to treat the 4 bytes as a little endian uint32.
set BTCMagic 0xD9B4BEF9

# Block Magic sanity check
if {[uint32] != $BTCMagic} {
  move -4
  error "[format "Bad Magic %4X" [hex 4] ]"
}

# Display the block metadata
move  -4
bytes  4 "Magic"
uint32   "Block length"

# Process actual block data
section "Block header" {
  uint32 -hex "version"
  bytes 32    "prev blk hash"
  bytes 32    "Merkle root"
  unixtime32  "time"
  uint32      "bits"
  uint32      "nonce"
}

# get the number of transactions for the block
set blockTxnum [getVarint]

# There may be hundreds of transactions. Make a collapsed section to keep the overview initially brief.
section -collapsed "TX COUNT $blockTxnum"  {
  for {set tx 0} {$tx < $blockTxnum} {incr tx} {
    section -collapsed "Transaction $tx" {     
      set aScriptSigNotZero 0

      uint32 -hex "Tx version"
  
      # if next varint is 0 then we've read a (single byte) marker and it's a SegWit transaction. 
      # if the varint is non-zero it's the actual number of inputs
      set nInputs [getVarint]
      if {$nInputs == 0} {
        # it's the marker and this is a SegWit transaction. read witness data later.
        set segwit 1
  
        # call out marker and flag byte
        move -1
        uint8 "marker"
        # flag must be non-zero (initally 1 -- see BIP 0141)
        uint8 "flag" 
        
        # now get the actual number of inputs
        set nInputs [getVarint]
      }  else {
        set segwit 0
      }
      
      set aScriptSigNotZero 0
      # process the inputs.
      section -collapsed "INPUT COUNT $nInputs"  {
        for {set k 0} {$k < $nInputs} {incr k} {  
          section "Input $k" {
            bytes 32  "UTXO"
            uint32    "index"
            set nscriptbytes [getVarint "ScriptSig len"]
            if {$nscriptbytes > 0} {
              incr aScriptSigNotZero
              # if it's the Coinbase transaction and the first script byte is 0x3
              # then the next 3 bytes are the block height. must be 1st transaction
              # and 1st input
              set bheight [uint8]
              if {$tx == 0 && $k == 0 && $bheight == 3} { 
                uint24 "height"
                move -3 
              } 
              # move back to beginning of script 
              move -1
              bytes $nscriptbytes "ScriptSig"
              move -$nscriptbytes
              set idSPK [hex $nscriptbytes]
              if {![parseSPK $nscriptbytes $idSPK]} {return}
            } 

            uint32 -hex "nSequence"
          }
        }
      }  
      
      # outputs
      set nOutputs [getVarint]
      
      # process the outputs
      section -collapsed "OUTPUT COUNT $nOutputs"  {
        for {set k 0} {$k < $nOutputs} {incr k} {
          section "Output $k" {
            uint64 "Satoshi"
            move -8
            set numSats [uint64]
            set nscriptbytes [getVarint "ScriptPubKey len"]
if {$nscriptbytes <= 0} {
  entry "output nscriptbytes is bogus"  $nscriptbytes
  return
}
            bytes $nscriptbytes "ScriptPubKey"
#if {1 && $k == 0 && $tx == 64} {
            move -$nscriptbytes
            set idSPK [hex $nscriptbytes]
            if {![parseSPK $nscriptbytes $idSPK]} {return}
#}
          }
        }
      }
  
      #if it's a Segwit transaction process the witness data for each input
      if {$segwit} {
        section -collapsed "WITNESS DATA"  {
          # this is the witness data for each input
          for {set k 0} {$k < $nInputs} {incr k} {
            section "Witness Input $k" {
              set nwitstack [getVarint "STACK COUNT"]
              section -collapsed "Stack"  {
                for {set l 0} {$l < $nwitstack} {incr l} {
                  set nscriptbytes [getVarint]
                  set wType [witnessType $nscriptbytes]
              
                  switch $wType {
                    "wtbadDER" {
                      entry "short sig fails" $l
                      return
                    }
                    "wtDER" {
                      if {![decodeSig]} {
                        return
                      }
                    }
                    "wtOP_" {
                      if {![decodeMultiSig]} {
                        bytes $nscriptbytes "item [expr $l + 1] $nscriptbytes bytes"
                        # return
                      }
                    }
                    "wtPK" {
                      if {![decodePubKey $nscriptbytes]} {
                        return
                      }
                    }
                    "wtOP_0" {
                      move -1
                      uint8 "OP_0" 
                    }
                    "wtIDK" {
if {$nscriptbytes > 400} {
  entry "nsb too big" $nscriptbytes
  return
}
                      bytes $nscriptbytes "item [expr $l + 1] $nscriptbytes bytes"
                    }
                    default {
                      entry "unknown witness data type" $wType
                      return
                    }
                  }

                } ; # for each stack item
              }   ; # Section stack items   
            }     ; # Section Witness input   
          }       ; # for each input
        }         ; # Section Witness data
      }           ; # process Segwit data

      uint32 "nLockTime"
      
    } ; # Section single transaction
  } ; # for each transaction
} ; # Section all transactions
