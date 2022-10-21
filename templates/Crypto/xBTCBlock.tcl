# Binary Template for Bitcoin Core Block content: expanded version
#   Process a single Bitcoin block contained in a Bitcoin Core blk*.dat file. 
#
#   Bitcoin Core blk*.dat files begin with 4 Magic bytes. These Magic bytes serve as a preamble to each block 
#   in the blk*.dat file. When invoked this template will align correctly on the initial block in the blk*.dat
#   file which begins with the Magic bytes. Different blocks can be examined by using the Hex Fiend 'Anchor 
#   Template at Offset' feature and anchoring on any Magic bytes in the file.
#
#   By default ScriptSig, ScriptPubKey, and Witness data are simply labeled as Hex Fiend byte fields. Without using
#   the expansions cited below this Template displays the raw data for each Transaction in the block. Additional 
#   options for these data are avaialbale as follows. 
#
#     For each Transaction in the block this template will try and decode the contents of ScriptSigs and ScriptPubKeys 
#     accompanying inputs and outputs, respectively. Any ScriptPubKey or non-empty ScriptSig will be displayed as a
#     Hex Fiend byte field. Following that there will be a collapsed Hex Fiend Section called 'Decode'. Expanding
#     this Section will reveal a labeled version of the respective script content.
#
#     For Witness data there may be multiple items for each input. Each stack item for each input is displayed 
#     as a Hex Fiend byte field. There is a separate 'Decode' Section for each non-empty item for each input.
#
# This Template is offered AS-IS. The 'Decode' sections are best effort. To correctly interpret the context of a 
# Transaction requires examining the UTXO of each input. Examining UTXOs is beyond the scope of this Template. 
#
#



# Return a BTC varint value. Presence of an argument causes the varint to be displayed as a Hex Fiend 
# field with the argument as the label. The file pointer is left at the first byte past the varint.
proc getVarint {{label ""}} {
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
    
    if {$label != ""}  {
      move $moveit
      $type $label
    }

    return $val
}

proc isPubKey {} {
  set klen [uint8]
  set op [uint8]
  move -2
  set retval 1
  
  if {$klen == 0x21} {
    # compressed key?
    if {$op != 2 && $op != 3} {
      set retval 0
    }
  } elseif {$klen == 0x41} {
    # uncompressed key?
    if {$op != 4} {
      set retval 0
    }
  } else {
    set retval 0
  }
  
  return $retval
}

proc decodePubKey {len} {
  set retval 1
  
  if {$len == 33} {
    bytes $len "Compressed PubKey"
  } elseif {$len == 65} {
    bytes $len "Uncompressed PubKey"
  } else {
    bytes $len "Unk Key"
    set retval 0
  }
  
  return $retval
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
      if {$len == 33 || $len == 65} {
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
  return
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

# This proc tries to interpret contents of a Witness stack item. The Witness stack items each contain data whose length is
# specified by a preceeding byte count. The data are not script so we don't parse for opcodes as with ScriptSig and 
# ScriptPubKey. The data might represent an elemental structure like a signature or public key. 
#
# This proc is also used to suss out ScriptSig and ScriptPubKey data pushed onto the stack. Typically in this case 
# the data are elemental structures. Some of the potential values here are objects that would not be found as a 
# Witness stack item.
# 
# this proc leaves the file pointer at the byte after the length spec.
proc decodeStack {len} {
  if {$len == 20} {
    # Data is probably pushed hash. Don't try to interpret it. It's OK if we miss something we could have figured out.
    set type "stIDK"
  } else {
    # Try to guess the object. Key off the first two bytes. Could possibly interpret something we shouldn't.
    set op  [uint8]
    set op1 [uint8]
    move -2
    
    if {$op == 0x30 && $len >= 67 &&  $len <= 73} {
      set type "stDER"
      if {![isSignature $len]} {
        set type "stbadDERSig"
      }
    } elseif {$op == 81} {
      if {$op1 == 32} {
        # Version 1 SegWit: Taproot. 
        set type "stOP1TRPUBK"
      } else {
        # Simple numeric value
        set type "stOP_81-96"
      }
    } elseif {$op >= 82 && $op <= 96} {
      # Simple numeric value
      set type "stOP_81-96"
    } elseif {$len == 33 && ($op == 2  ||  $op == 3)} {
      # A compressed public key
      set type "stcPK"
    } elseif {$len == 65 && $op == 4} {
      # An uncompressed public key
      set type "stuPK"
    } elseif {$op == 0 && $op1 == 20} {
      # Version 0 SegWit
      set type "stOP0HASH20"
    } elseif {$op == 0 && $op1 == 32} {
      # Version 0 SegWit
      set type "stOP0HASH32"
    } else {
      set type "stIDK"
    }
  }
  return $type
}

proc initTemplate {} {
  global opcodeTable {}
  global opcodeTableLen
  
  set opcodeTable {  \
      {0 "OP_0"} \
     {76 "OP_PUSHDATA1"} \
     {77 "OP_PUSHDATA2"} \
     {78 "OP_PUSHDATA4"} \
    {106 "OP_RETURN"} \
    {118 "OP_DUP"} \
    {135 "OP_EQUAL"} \
    {136 "OP_EQUALVERIFY"} \
    {169 "OP_HASH160"} \
    {172 "OP_CHECKSIG"} \
    {173 "OP_CHKSIGVRFY"} \
    {174 "OP_CHECKMULTISIG"} \
    {175 "OP_CHKMULTISIGVRFY"} \
    {186 "OP_CHECKSIGADD"} \
  }  
  set opcodeTableLen [llength $opcodeTable]
  return
}

# Look for OpCode and map it to something interpretable for later display.
proc getOP_CODE {} {
  global opcodeTable {}
  global opcodeTableLen     
     
  set retval "OP_IDK"
  set auxval1 0   ; # skip-byte parameter for push opcodes; the bad opcode value if OP_IDK
  
  set OpCode [uint8]

  # First check for opcodes that do not have a singular representation
  if {$OpCode > 0  &&  $OpCode < 76} {
    set retval "OP_PUSH"
    set auxval1 $OpCode
  } elseif {$OpCode > 80  &&  $OpCode < 97} {
    set retval "OP_1-16"
    set auxval1 [expr $OpCode - 80]
  } else {
    # OK to now search the list
    set ocitem [lsearch -index 0 -inline $opcodeTable $OpCode]
    if {$ocitem != ""} {
      set retval [lindex $ocitem 1]
    }
  }
    
  # Post processing for OP_PUSHDATAx special cases where the info after the opcode is the number of bytes 
  # to push. Similar to varint. The opcode may specify different size count objects (1, 2, or 4 bytes).
  if {$retval == "OP_PUSHDATA1"} {
    set auxval1 [uint8]
  } elseif {$retval == "OP_PUSHDATA2"} {
    set auxval1 [uint16]
  } elseif {$retval == "OP_PUSHDATA4"} {
    set auxval1 [uint32]
  }
  
  # If the Opcode hasn't been discovered save the offending Opcode.
  if {$retval == "OP_IDK"} {
    set auxval1 $OpCode
  }
  
  return [list $retval $auxval1]
}

# Return a list of op codes. If the opcode pushes data the data are skipped to get to the next opcode.
proc parseScript {len}  {
  set OPCList {}
  
  for {set i 0} {$i < $len} {incr i} {
    set opcode [getOP_CODE]
    lappend OPCList $opcode
    lassign $opcode cmd auxval1

    if {$cmd == "OP_IDK"} {
      return $OPCList
    }
    
    # Skip over the bytes pushed for OP_PUSH or OP_PUSHDATAx. The loop index increment must also account for byte count 
    # field for OP_PUSHDATAx opcodes.
    if {$cmd == "OP_PUSH"} {
      incr i $auxval1
      move $auxval1
    } elseif {$cmd == "OP_PUSHDATA1"} {
      incr i [expr $auxval1 + 1]
      move $auxval1
    } elseif {$cmd == "OP_PUSHDATA2"} {
      incr i [expr $auxval1 + 2]
      move $auxval1
    } elseif {$cmd == "OP_PUSHDATA4"} {
      incr i [expr $auxval1 + 4]
      move $auxval1
    }
  }
  return $OPCList
}

proc showSpecial {type len label flags} {
  if {[expr $flags & 2]} {
    section -collapsed "more" {
      uint8 $type
      uint8 "OP_PUSH"
      bytes $len $label
    }
  } else {
    uint8 $type
    uint8 "OP_PUSH"
    bytes $len $label
  }
}

# Display data previously interpreted from the stack. It is either Witness stack data or possibly data pushed in a ScriptSig or
# ScriptPubKey script.
#
# this procedure leaves the pointer at the end of the data
proc showStack {type len {flags 0}} { 
  set retval 1
                   
  switch $type {
    "stbadDERSig" {
      entry "DER hint fails" $type
      set retval 0
    }
    "stDER" {
      # Object already verified as a DER signature. Just display it.
      decodeSig
    }
    "stOP_81-96" {
      # Might be a multisig
      if {![decodeMultiSig]} {
        if {$len == 20} {
          bytes $len "<hash>"
        } else {
          bytes $len "nonMS data"
        }
      }
    }
    "stcPK" {
      # Might be a compressed public key
      if {![decodePubKey $len]} {
        set retval 0
      }
    }  
    "stuPK" {
      # Might be an uncompressed public key
      if {![decodePubKey $len]} {
        set retval 0
      }
    }
    "stOP1TRPUBK" {
      # Version 1 SegWit: Taproot
      showSpecial "OP_1" 32 "<P2TR PubKey>" $flags
    }
    "stOP0HASH20" {
      showSpecial "OP_0" 20 "<PubKey hash>" $flags
    }
    "stOP0HASH32" {
      showSpecial "OP_0" 32 "<Script hash>" $flags
    }
    "stIDK" {
      # No specific clue to data on stack. There are a few cases we can guess.
      if {$len == 20 || $len == 32} {
        # Probably a key hash or a script hash
        bytes $len "<hash>"
      } elseif {[expr $flags & 1]} {
        # Arbitrary data (sometimes printable characters) after an OP_RETURN (which guarantees script result is not TRUE)
        bytes $len "<data>"
      } else {
        # I Don't Know
        bytes $len "IDK bytes"
      }
    }
    default {
      entry "unknown stack data type" $type
      set retval 0
    }
  }
  return $retval
}

# Display script detail for each opcode discovered in ScriptSig or ScriptPubKey.
proc decodeParse {opcodes len {sats 0}} {
  # Move the input pointer back and process ScriptSig or ScriptPubKey in parallel with the Opcode list and display info in
  # Hex Fiend fields.
  move -$len
  
  set done 0
  set retval 1
  set flags 0
  set llen [llength $opcodes]
  
  section -collapsed "Decode" {
    for {set i 0} {$i < $llen  &&  $done == 0} {incr i} {
      set cur [lindex $opcodes $i]
      lassign $cur code a1
      set ostr $code

      if {$code == "OP_1-16"} { 
        # See if this is the special case of SegWit Version 1 P2TR public key
        set type [decodeStack $a1]
        if {$type == "stOP1TRPUBK"} {
          set retval [showStack $type $a1 $flags]
          set done 1
        } else {
          set ostr [format "OP_%d" $a1]
          uint8 $ostr
        }
        set flags [expr $flags | 2]
      } elseif {$code == "OP_PUSHDATA1" || $code == "OP_PUSHDATA2" || $code == "OP_PUSHDATA4"} {
        set flags [expr $flags | 2]
        uint8 $ostr
        if {$code == "OP_PUSHDATA1"} {
          set size "uint8"
        } elseif {$code == "OP_PUSHDATA2"} {
          set size "uint16"
        } else {
          set size "uint32"
        }
        $size "push"
        set type [decodeStack $a1]
        set retval [showStack $type $a1 $flags]
        if {$retval == 0} {set done 1}
      } elseif {$code == "OP_PUSH"} {
        set flags [expr $flags | 2]
        uint8 $ostr
        set type [decodeStack $a1]
        set retval [showStack $type $a1 $flags]
        if {$retval == 0} {set done 1}
      } elseif {$code == "OP_IDK"} {
        entry "Decode Opcode fail" $cur
        set retval 0
        set done 1
      } else {
        uint8 $ostr
        if {$code == "OP_RETURN"} {
          if {$sats != 0} {
            entry "(Sats unspendable)" ""
          }
          # provide context to subsequent procs that because of OP_RETURN the script will fail 
          set flags [expr $flags | 1]
        }
      }
      set flags [expr $flags | 2]
    }
  }
  
  return $retval
}

# ***********************************************************************************************************************


# DEBUG SETUP   ********

global CONTEXT
global curTx
global kcnt
global debugMsgs

set op_ss  {}
set ssTarget {}
set nssTar [llength $ssTarget]

set op_spk {}
set spkTarget {}
set nspkTar [llength $spkTarget]

set debugMsgs {}
set DEBUG 1
set CONTEXT "Init"

# END DEBUG SETUP   ********



set nullstr ""
set exitMsg [format "Exit: normal"]
set ALLDONE 0
set szFile [len]

initTemplate

# BTC Magic is 4 bytes (0xF9BEB4D9) but it is more convenient to treat the 4 bytes as a little endian uint32.
set BTCMagic 0xD9B4BEF9

# Block Magic sanity check
if {[uint32] != $BTCMagic} {
  move -4
  entry " " $nullstr
  entry [format "Exit: Bad Magic %4X" [hex 4] ] $nullstr
  entry " " $nullstr
  return
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

# There may be thousands of transactions. Make a collapsed section to keep the overview initially brief.
section -collapsed "TX COUNT $blockTxnum"  {
  set Coinbase 1
  set iscb "(Coinbase)"
  for {set curTx 0} {$curTx < $blockTxnum && $ALLDONE == 0} {incr curTx} {
    section -collapsed "Transaction $curTx $iscb" {     
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
    
      # process the inputs.
      section -collapsed "INPUT COUNT $nInputs"  {
set CONTEXT "Input"
        for {set kcnt 0} {$kcnt < $nInputs && $ALLDONE == 0} {incr kcnt} {  
          section "Input $kcnt" {
            bytes 32  "UTXO"
            uint32    "index"
            set nscriptbytes [getVarint "ScriptSig len"]
            if {$nscriptbytes < 0  ||  $nscriptbytes > $szFile} {
              set exitMsg [format "Exit: Bogus ScriptSig nscriptbytes=%d  Tx=%d input=%d" $nscriptbytes $curTx $kcnt]
              set ALLDONE 1
              continue
            }
            if {$nscriptbytes > 0} {
              # Check for block height. If it's the Coinbase transaction and the first script byte 
              # is 0x3 then the next 3 bytes are the block height.
              if $Coinbase {
                set bheight [uint8]
                if {$bheight == 3} { 
                  uint24 "height"
                  move -3 
                } 
                # Move back to beginning of script and start over.
                move -1
              }
              bytes $nscriptbytes "ScriptSig"
              
              # Process the script if it's not the Coinbase input.
              if !$Coinbase {
                move -$nscriptbytes
                set opcode [parseScript $nscriptbytes]
if {$DEBUG} {
                # Look for target opcodes in list of those found.
                for {set n 0} {$n < $nssTar} {incr n} {
                  set t [lindex $ssTarget $n] 
                  for {set m 0} {$m < [llength $opcode]} {incr m} {
                    set oc [lindex [lindex $opcode $m] 0]
                    if {$oc ==  $t} {
                      set aux [lindex [lindex $opcode $m] 1]
                      lappend op_ss [list $curTx $kcnt $t $aux]
                    }
                  }
                }
}

                if { ![decodeParse $opcode $nscriptbytes] } {
                  set exitMsg [format "Exit: ScriptSig decodeParse fail Tx: %d  input %d " $curTx $kcnt]
                  set ALLDONE 1
                  continue
                } 
              } else {
                  set Coinbase 0
                  set iscb ""
              }
            } else {
if {$DEBUG} {
              for {set n 0} {$n < $nssTar} {incr n} {
                set t [lindex $ssTarget $n] 
                if {$t == ""} {
                  lappend op_ss [list $curTx $kcnt "<null>"]
                }
              }
}  
            } 
            uint32 -hex "nSequence"
          } 
        }
      }  
      
      # outputs
      set nOutputs [getVarint]
    
      # process the outputs
      section -collapsed "OUTPUT COUNT $nOutputs"  {
set CONTEXT "Output"
        for {set kcnt 0} {$kcnt < $nOutputs && $ALLDONE == 0} {incr kcnt} {
          section "Output $kcnt" {
            set sats [uint64]
            move -8
            uint64 "Satoshi"
            set nscriptbytes [getVarint "ScriptPubKey len"]
            if {$nscriptbytes <= 0  ||  $nscriptbytes > $szFile} {
              set exitMsg [format "Exit: Bogus ScriptPubKey nscriptbytes=%d Tx=%d output=%d" $nscriptbytes $curTx $kcnt]
              set ALLDONE 1
              continue
            }
            bytes $nscriptbytes "ScriptPubKey"
            move -$nscriptbytes
            set opcode [parseScript $nscriptbytes]
if {$DEBUG} {
            # Look for target opcodes in list of those found.
            for {set n 0} {$n < $nspkTar} {incr n} {
              set t [lindex $spkTarget $n]
              for {set m 0} {$m < [llength $opcode]} {incr m} {
                set oc [lindex [lindex $opcode $m] 0]
                if {$oc ==  $t} {
                  set aux [lindex [lindex $opcode $m] 1]
                  lappend op_spk [list $curTx $kcnt $t $aux]
                }
              }
            }
}
            if { ![decodeParse $opcode $nscriptbytes $sats] } {
              set exitMsg [format "Exit: ScriptPubKey decodeParse fail Tx: %d  output %d " $curTx $kcnt]
              set ALLDONE 1
              continue
            }         
          }
        }
      }

      #if it's a Segwit transaction process the witness data for each input
      if {$segwit} {
        section -collapsed "WITNESS DATA"  {
          # this is the witness data for each input
set CONTEXT "Witness"
          for {set kcnt 0} {$kcnt < $nInputs && $ALLDONE == 0} {incr kcnt} {
            section "Witness Input $kcnt" {
              set nwitstack [getVarint "STACK COUNT"]
              section -collapsed "Stack"  {
                for {set l 0} {$l < $nwitstack} {incr l} {  
                  set ilabel [format "Item %d length" [expr $l + 1]]
                  set nscriptbytes [getVarint $ilabel] 
                  if {$nscriptbytes < 0  ||  $nscriptbytes > $szFile} {
                    set exitMsg [format "Exit: Bogus Witness stack nscriptbytes=%d Tx=%d input=%d item=%d" $nscriptbytes $curTx $kcnt $l]
                    set ALLDONE 1
                    continue
                  }
                  if {$nscriptbytes > 0 } {
                    set ilabel [format "Item %d" [expr $l + 1]]
                    bytes $nscriptbytes $ilabel    
                    move -$nscriptbytes
                    section -collapsed "Decode" {
                      set wType [decodeStack $nscriptbytes]
                      if {![showStack $wType $nscriptbytes]} { 
                        set exitMsg [format "Exit: Witness showSrack fail Tx: %d  input %d " $curTx $kcnt]
                        set ALLDONE 1
                        continue
                      }
                    }
                  } 
                } ; # for each stack item
              }   ; # Section stack items   
            }     ; # Section Witness input   
          }       ; # for each input
        }         ; # Section Witness data
      }           ; # process Segwit data

      if {$ALLDONE == 0} {
        uint32 "nLockTime"
      } 
    } ; # Section single transaction
  } ; # for each transaction
} ; # Section all transactions


entry " " $nullstr
entry $exitMsg $nullstr
entry " " $nullstr



# DEBUG/INSTRUMENTATION   ********
if {[llength $debugMsgs] > 0}  {
  entry [format "%d debug nmessages" [llength $debugMsgs]] $nullstr
  entry " " $nullstr
  for {set i 0} {$i < [llength $debugMsgs]} {incr i} {
    entry [lindex $debugMsgs $i] $nullstr
  }
}


if {[llength $op_ss] > 0} {
  entry "SS Target opcodes" $ssTarget
  entry "op_ss len" [llength $op_ss]
  section -collapsed "op_ss" {
    for {set i 0} {$i < [llength $op_ss]}  {incr i} {
     entry [format "op_ss %d" $i] [lindex $op_ss $i]
    }
  }
}

if {[llength $op_spk] > 0} {
  entry "SPK Target opcodes" $spkTarget
  entry "op_spk len" [llength $op_spk]
  section -collapsed "op_spk" {
    for {set i 0} {$i < [llength $op_spk]}  {incr i} {
      entry [format "op_spk %d" $i] [lindex $op_spk $i]
    }
  }
}

# END DEBUG/INSTRUMENTATION   ********
