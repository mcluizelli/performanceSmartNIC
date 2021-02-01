#!/bin/bash

#PATH=/home/mcluizelli/

#This scripts generates all P4 files
PATH_NFP=/opt/netronome/bin
PATH_RTE=/opt/netronome/p4/bin
PATH_NFP_SIM=/opt/nfp-sim/bin
PATH_MG=/opt/MoonGen

######## Remote Paths (machine .69)
PATH_REMOTE_MG=/home/mcluizelli/MoonGen 

PATH_EXP=/home/mcluizelli/performanceP4

#/examples/netronome-packetgen/packetgen.lua -tx 2 -rx 2 --dst-ip 10.2.0.10 --dst-ip-vary 0.0.0.0

P4FILENAME="myPDP.p4"
numRegister=200
sizeRegister=256


#need to verify iff rte is on
systemctl start nfp-sdk6-rte
systemctl start nfp-sdk6-rte2

rm -r code*
rm $P4FILENAME

p4File_preambule(){

    echo "#include <core.p4>
          #include <v1model.p4>
          const bit<16> TYPE_IPV4 = 0x800;" >> $P4FILENAME

}

p4RegisterDeclaration(){
    
    if [ $1 -ne 0 ]
    then
        echo "register<bit<$sizeRegister>>($1) myRegister;" >> $P4FILENAME
    fi

}

p4File_mid(){

    echo "
    register<bit<64>>((bit<32>)2) latency;
    /*************************************************************************
    *********************** H E A D E R S  ***********************************0
    *************************************************************************/
    
    typedef bit<9>  egressSpec_t;
    typedef bit<48> macAddr_t;
    typedef bit<32> ip4Addr_t;

    header ethernet_t {
                macAddr_t dstAddr;
                macAddr_t srcAddr;
                bit<16>   etherType;
    }

    header ipv4_t {
                bit<4>    version;
                bit<4>    ihl;
                bit<8>    diffserv;
                bit<16>   totalLen;
                bit<16>   identification;
                bit<3>    flags;                                                                                                                          bit<13>   fragOffset;
                bit<8>    ttl;
                bit<8>    protocol;
                bit<16>   hdrChecksum;
                ip4Addr_t srcAddr;
                ip4Addr_t dstAddr;
    }

    struct metadata {
                /* empty */
    }

    header intrinsic_metadata_t {
        //sec[63:32], nsec[31:0]
            bit<64> ingress_global_timestamp;
            bit<64> current_global_timestamp;
    }//96 bits / 12 bytes
    
    struct headers {
                ethernet_t   ethernet;
                ipv4_t       ipv4;
                intrinsic_metadata_t    intrinsic_metadata;
   }

    /*************************************************************************
    *********************** P A R S E R  ***********************************
    *************************************************************************/

    parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

                state start {
                        transition parse_ethernet;
                }

                state parse_ethernet {
                        packet.extract(hdr.ethernet);
                        transition select(hdr.ethernet.etherType){
                                TYPE_IPV4: parse_ipv4;
                                default: accept;

                        }

                }

                state parse_ipv4 {
                        packet.extract (hdr.ipv4);
                        transition accept;
                }
    }

    /*************************************************************************
    ************   C H E C K S U M    V E R I F I C A T I O N   *************
    *************************************************************************/

    control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
                apply {  }
    }

/*******************************************************************************
**************  I N G R E S S   P R O C E S S I N G ****************************
*******************************************************************************/

/* Esse bloco e sequencia, sendo necessario que os elementos chamados estejam
 * descritos antes da sua chamada
  */
   control MyIngress(inout headers hdr, inout metadata meta,
                    inout standard_metadata_t standard_metadata) {
                
               // register<bit<64>>((bit<32>)2) latency;

                action drop() {
                     mark_to_drop();
                }

                action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
                     standard_metadata.egress_spec = (bit<16>)port;
                     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                     hdr.ethernet.dstAddr = dstAddr;" >> $P4FILENAME
    

#reading
    
    echo "bit<$sizeRegister> r_aux;" >> $P4FILENAME 

    if [ $i -ne 0 ]
    then
        echo "myRegister.read(r_aux, 0);" >> $P4FILENAME
    fi
    aux=$1
    aux=$aux-1
    for i in $(seq $((aux)) )
    do
        echo "myRegister.read(r_aux, $i);" >> $P4FILENAME
    done
    
    echo "
                                                                                                                                                          }

                                                                                                                                                         table ipv4_lpm {
                                                                                                                                                                key = {
                                                                                                                                                                    hdr.ipv4.dstAddr: lpm;
                      }
                                                                                                                                                                actions = {
                                                                                                                                                                    ipv4_forward;
                                                                                                                                                                    drop;

                          NoAction;

                     }

                    size = 1024;
                    default_action = drop();

                }


                apply {
                    
                    if ( hdr.ipv4.isValid() ){
                        ipv4_lpm.apply();
                        latency.write((bit<32>)0, hdr.intrinsic_metadata.ingress_global_timestamp);
                                                                                                                                                 }

                                                                                                                                }
                                                                                                                                                                                                                                                                                            }


/*******************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   **************************
  *******************************************************************************/

   control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
                 apply {
                     latency.write((bit<32>)1, hdr.intrinsic_metadata.current_global_timestamp);
                 }
                
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

   control MyComputeChecksum(inout headers hdr, inout metadata meta) {
                 apply {
                    update_checksum(hdr.ipv4.isValid(),{ hdr.ipv4.version,hdr.ipv4.ihl,hdr.ipv4.diffserv,hdr.ipv4.totalLen,hdr.ipv4.identification,hdr.ipv4.flags,hdr.ipv4.fragOffset,hdr.ipv4.ttl,hdr.ipv4.protocol,hdr.ipv4.srcAddr,hdr.ipv4.dstAddr },hdr.ipv4.hdrChecksum,HashAlgorithm.csum16);
                 }
    }


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
                
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
                                                                                                                                             }
}                                                                                                                                     

                                                                                                                                          /*************************************************************************
                                                                                                                                          ***********************  S W I T C H  *******************************
                                                                                                                                          *************************************************************************/

                                                                                                                                            V1Switch(
                                                                                                                                                MyParser(),
      MyVerifyChecksum(),
      MyIngress(),
      MyEgress(),
      MyComputeChecksum(),
      MyDeparser()
                                                                                                                                                                                                                                                                                        ) main;


    " >> $P4FILENAME
}

getPktLatency(){
    valid=true
    count=1

    while [ $valid ] 
    do
    
    nPackets="$(sudo /opt/netronome/p4/bin/rtecli -p 20207 registers get -r latency -i 0)"
    #echo "${nPackets}"
    startValueStr=${nPackets:12:8}
    endValueStr=${nPackets:34:8}
                                
    startValue=$(( 16#$startValueStr ))
    endValue=$(( 16#$endValueStr ))

    latency=$[endValue-startValue]
    latencyVector[$count]=$latency
    #echo "${latency}"
                                                        
    sleep 0.1s

    if [ $count -eq 50 ]  
    then
      break
    fi
    ((count++))
 done

 for i in "${latencyVector[@]}"
  do
    echo $i >> $1-latency.txt
  done
}

getNicPower(){
    valid=true
    count=1

    while [ $valid ] 
    do
        readPower="$(sudo /opt/netronome/bin/nic-power | grep current)"
        powerValue=${readPower:9:6}
        powerVector[$count]=$powerValue
        sleep 0.1s
        if [ $count -eq 30 ]
        then
            break
        fi
            ((count++))
        done

        for i in "${powerVector[@]}"
        do
            echo $i >> $1-power.txt
        done
}

configRemoteMachine(){
    
    PARAM_MG="$PATH_REMOTE_MG/examples/netronome-packetgen/packetgen.lua -tx 2 -rx 2 --dst-ip 10.1.0.10  --dst-ip-vary 0.0.0.0 --timeout 10 -fp outAux.txt"
    
    #ssh -t root@200.132.136.69 '/home/mcluizelli/MoonGen/build/MoonGen /home/mcluizelli/MoonGen/examples/netronome-packetgen/packetgen.lua -tx 2 -rx 2 --dst-ip 10.1.0.10 --dst-ip-vary 0.0.0.0 --timeout 10 -fp outAux'
    size=$2

    nohup ssh -t root@200.132.136.67 '/opt/MoonGen/build/MoonGen /opt/MoonGen/examples/netronome-packetgen/packetgen.lua -tx 0 -rx 0 --dst-ip 10.1.0.10 --dst-ip-vary 0.0.0.0 --timeout 35 -fp outAux -ps '$size'' & #>/dev/null 
    
    #time to bring up DPDK/MoonGen
    sleep 20
    
    aux=$1
    echo $aux

    fileNameAux=$aux-pktSize-$2-$sizeRegister

    #Measure NIC latency
    getPktLatency $fileNameAux
    
    #Measure NIC power
    getNicPower $fileNameAux

    #Wait a few more seconds until DPDK/MoonGen finish
    sleep 20

    scp root@200.132.136.67:/root/outAux.txt $PATH_EXP

    mv $PATH_EXP/outAux.txt $PATH_EXP/$aux-pktSize-$2-$sizeRegister.txt

    ssh -t root@200.132.136.67 'rm /root/outAux.txt'
    sleep 1
}


main(){
 
    $PATH_RTE/rtecli -p 20206 design-unload
    $PATH_RTE/rtecli -p 20207 design-unload
    

    for iRegisterSize in 10 20 30 40 50 60 70 80 90 100 110 120 130 140 150 160 170 180 190 200
    do
       #register width
       for jRegisterWidth in 16  32 64 128 256 512
       do 
           sizeRegister=$jRegisterWidth
       
           #delete old files
           rm -r code*
           rm $P4FILENAME

           #create P4 file according to the number of register
           p4File_preambule $iRegisterSize
           p4RegisterDeclaration $iRegisterSize
           p4File_mid $iRegisterSize

           #compiling p4 code to Netronome
            echo "Compiling..."
           /opt/netronome/p4/bin/nfp4build --output-nffw-filename $PATH_EXP/code/firmware.nffw -4 $PATH_EXP/myPDP.p4 --sku nfp-4xxx-b0 --platform hydrogen --reduced-thread-usage  --no-shared-codestore --debug-info --nfp4c_p4_version 16 --nfp4c_p4_compiler p4c-nfp --nfirc_default_table_size 65536 --nfirc_no_all_header_ops --nfirc_implicit_header_valid --nfirc_no_zero_new_headers --nfirc_multicast_group_count 16 --nfirc_multicast_group_size 16 --nfirc_mac_ingress_timestamp #>/dev/null 
           
           echo "Loading into NICS..."
           #loading new firmware to the Netronomes
           #nfp-config.sh nl $PATH_EXP/code/firmware.nffw $PATH_EXP/myconfig.p4cfg              
           /opt/netronome/p4/bin/rtecli -p 20207 design-load -f $PATH_EXP/code/firmware.nffw -c $PATH_EXP/myconfig.p4cfg 

           for pktSize in 64  128 256 512 1024 1500
           do
              #executing traffic generator MoonGen
              echo "Running MG pktSize:" $pktSize
              configRemoteMachine $iRegisterSize $pktSize
           done
           #$PATH_RTE/rtecli -p 20206 design-unload
           #$PATH_RTE/rtecli -p 20207 design-unload
     done
done

}

main
