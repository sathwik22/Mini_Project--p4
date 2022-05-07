
#include <v1model.p4>


// sudo /opt/netronome/p4/bin/nfp4build -o verifier.nffw -p out_dir -4 verifier-Copy.p4 -l lithium --nfp4c_p4_version 16 --nfp4c_I /opt/netronome/p4/include/16/p4include/
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_UDP = 0x11;
//consit bit<16> TYPE_AUTH = 0x15;
const bit<16> TYPE_AUTH = 0x1d; // hex of 29

#define MAX_UAVS 0xffff
#define MAX_CRPairs 16000

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<32> reg_entry_t;
typedef bit<32> reg_index_t;
typedef bit<32> hash_width_t;
typedef bit<16> port_t;
typedef bit<32> random_number_width_t;
/******************** HEADERS ********************
************************************************/

header ethernet_h 
{
    mac_addr_t destMac;
    mac_addr_t srcMac;
    bit<16> ethType;
}

header ipv4_h
{
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ipv4_addr_t srcAddr;
    ipv4_addr_t dstAddr;
}

header udp_h
{
    port_t srcPort;
    port_t dstPort;
    /* if the message is authentication message from UAV, payload length will be 98 i.e. 0x62. 
    Payload length is used to identify authentication message */
    bit<16> udpLen; 
    bit<16> udpChkSum;
}

header auth_h 
{
    bit<8> authMsgType;
    bit<32> challenge1;
    bit<32> challenge2;
    bit<32> randomNumber;
    bit<32> uavIdentifier;
    bit<32> prTime;
}

struct ingress_headers_t 
{
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    auth_h auth;
}

struct ingress_metadata_t
{
};




/************************************************
******************** PARSER *********************
************************************************/
parser MyParser (packet_in packet, 
                 out ingress_headers_t hdr, 
                 inout ingress_metadata_t meta, 
                 inout standard_metadata_t standard_metadata)
{
       state start {
       // packet.extract(standard_metadata);
        //packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    
    state parse_ethernet
    {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType)
        {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4
    {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol)
        {
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }
    
    state parse_udp
    {
        packet.extract(hdr.udp);
        transition select(hdr.udp.udpLen)
        {
            TYPE_AUTH: parse_auth;
            default: accept;
        }
    }
    
    state parse_auth
    {
        packet.extract(hdr.auth);
        transition accept;
    }

}


/************************************************
************** Checksum Verification ************
************************************************/

control MyVerifyChecksum (inout ingress_headers_t hdr, inout ingress_metadata_t meta)
{
    apply 
    { 

    }
}

/************************************************
*************** Ingress Processing **************
************************************************/ 

control MyIngress (inout ingress_headers_t hdr, 
        inout ingress_metadata_t meta, 
        inout    standard_metadata_t standard_metadata)
{
    bit<32> ch1 = 0;
    bit<32> ch2 = 0;
    bit<32> resp1 = 0;
    bit<32> resp2 = 0;
    bit<32> CRPIndex; /*points to a specific CR pair of the UAV */


    reg_index_t reg_index = 0;
    hash_width_t hashValue = 0;
    hash_width_t challengeHashSent = 0;
    hash_width_t challengeHashRecvd = 0;
    random_number_width_t rndNumber = 0;
    random_number_width_t newRnd = 0;
    bit <32> tmp = 0;
    bit <16> tmpPort = 0;
    mac_addr_t tmpMac = 0;

    action random_generator(){
    random(rndNumber,(bit<32>)0,(bit<32>)65500);
    }

    action createHash1(){
    //hash<hash_width_t>(HashAlgorithm_t.CRC32) hash1;
    hash(challengeHashSent,HashAlgorithm.crc32);
    //Hash<hash_width_t>(HashAlgorithm_t.CRC32) hash2;
    }
    
    action createHash2(){
    //Hash<hash_width_t>(HashAlgorithm_t.CRC32) hash1;
    //hash<hash_width_t>(HashAlgorithm_t.CRC32) hash2;
    hash(challengeHashRecvd,HashAlgorithm.crc32);
    }

    // Register<type of reg entry, type of reg index>(size)
    register <reg_entry_t>(MAX_UAVS) challenge_hash_reg;
    /*register <reg_entry_t>(challenge_hash_reg) 
    write_reg = {
        void apply (inout reg_entry_t register_data) {
            register_data = challengeHashSent;

        }
    };
    
    register <reg_entry_t>(challenge_hash_reg) 
    read_reg = {
        void apply (inout reg_entry_t register_data, out bit<32> hashSent) {
            hashSent = register_data;
        }
    };*/

    action send(port_t port) {
        
        tmpMac = hdr.ethernet.destMac;
        hdr.ethernet.destMac = hdr.ethernet.srcMac;
        hdr.ethernet.srcMac = tmpMac;
        tmp = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tmp;
        tmpPort = hdr.udp.dstPort;
        hdr.udp.dstPort = hdr.udp.srcPort;
        hdr.udp.srcPort = tmpPort;

        hdr.udp.udpChkSum=0;

        standard_metadata.egress_spec = port;
    }


    action drop()
    {
            mark_to_drop();
    }
    
    /* random  number range should be equal to the number of entries in CRPair table.*/

    action getRandomCRPairIndex()
    {
        //CRPIndex will range from  0 - 2^31 as one entry have two CRPairs.
        random(CRPIndex,(bit<32>)0,(bit<32>)5000);
    }

    action retreiveCRPairs(bit<32> challenge1, bit<32> response1,
                           bit<32> challenge2, bit<32> response2)
    {
        ch1 = challenge1;
        resp1 = response1;
        ch2 = challenge2;
        resp2 = response2;
    }

    table UAV_registration
    {
        key = {
            hdr.auth.uavIdentifier : exact;
//            hdr.ethernet.srcMac : exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
        size = MAX_UAVS;
    }

    table UAV_CRPairs
    {
        key = {
            hdr.auth.uavIdentifier : exact;
//            hdr.ethernet.srcMac : exact;
            CRPIndex : exact;
        }
        actions = {
            retreiveCRPairs;
            drop;
        }
        default_action = drop();
        size = MAX_CRPairs;
    }

    apply
    {
        if (hdr.ipv4.isValid() && hdr.udp.isValid())
        {
            /* check if the packet is from UAV and is an authentication packet. 
            Mavlink protocol uses udp port 14550 and authentication packet will 
            have udp length 0x62 */
            if(hdr.udp.dstPort == 14550 && hdr.udp.udpLen == TYPE_AUTH)
            {
                if(hdr.auth.isValid())
                {
                    if(UAV_registration.apply().hit)
                    {
                       hdr.auth.prTime = standard_metadata.ingress_global_timestamp[31:0];  
                        /* Check if it is an authentication request packet or an authentication response.*/
                        if(hdr.auth.authMsgType == 0) //auth request
                        {
                            /* Check if this is a registered UAV. UAVs are registered using their 
                               MAC address and is stored in UAVRegistraion Table. If the table lookup 
                               with MAC address as key is a hit, the UAV is registered, else it is not 
                               and drop the packet. */

                            /*get a random index to UAV_CRPairs Table. This helps us choose the 
                              CR pairs randomly. */

                            random(CRPIndex,(bit<32>)0,(bit<32>)65500); 
                            CRPIndex = CRPIndex & 0x0000000f; //temporary for testing as only few entries are added to the table
                            if(UAV_CRPairs.apply().hit)
                            {

                                /* Compute the hash of the retreived CR pairs. 
                                 *  hashValue = Hash(R1,R2,RandomNumber)
                                 *  newRandom  = randomNumber | R1 | R2
                                 *  This newRandom is then sent along with C1 and C2 as the challenge to the UAV
                                 */
                                random(rndNumber,(bit<32>)0,(bit<32>)65500);
                                challengeHashSent = createHash1.get({resp1, resp2, rndNumber});

                                /*TODO REMOVE The below code line, that is added for testing alone */
                                //    challengeHash = 0xaabbccdd;
                                resp1 = resp1 | resp2;
                                hdr.auth.randomNumber = resp1 ^ rndNumber;
                                //           newRnd = rndNumber ^ tmp;

                                //  newRnd = (resp1 | resp2) ^ rndNumber;

                                /* Send the newRandom and challenge1 and challenge to the UAV. 
                                   Fill the authentication header values, UDP and IP header values (length and checksum)
                                 */
                                hdr.auth.authMsgType = 1; //auth challenge message
                                hdr.auth.challenge1 = ch1;
                                hdr.auth.challenge2 = ch2;

                              //  hdr.udp.udpChkSum=0;
                                /*Save this computed hash value to a register so that this can be verified when we 
                                  receive the auth response message from the UAV 
                                  as a response to this challange.
                                 */
                                /* Compute the index for the register entry */
                                 //  reg_index = createHash2.get({hdr.auth.uavIdentifier});
                             //   write_reg.execute(reg_index);
                                //write_reg.execute(hdr.auth.uavIdentifier);
                              challenge_hash_reg.write(challengeHashSent,hdr.auth.uavIdentifier);
                              //  write_reg.execute(0);


                                send(standard_metadata.ingress_port);
                            /*    tmpMac = hdr.ethernet.destMac;
                                hdr.ethernet.destMac = hdr.ethernet.srcMac;
                                hdr.ethernet.srcMac = tmpMac;
                                tmp = hdr.ipv4.srcAddr;
                                hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                                hdr.ipv4.dstAddr = tmp;
                                tmpPort = hdr.udp.dstPort;
                                hdr.udp.dstPort = hdr.udp.srcPort;
                                hdr.udp.srcPort = tmpPort;
                                */
                            }
                        }
                        else if(hdr.auth.authMsgType == 2) //auth response to the challenge
                        {

                            /* Retrieve the earlier computed hash on the reponses and random number and verify against the received one*/
                            /* Compute the index for the register entry */
                            /*   reg_index = createHash2.get({hdr.ethernet.srcMac,
                                 hdr.ethernet.destMac,
                                 hdr.ipv4.srcAddr,
                                 hdr.ipv4.dstAddr,
                                 hdr.ipv4.protocol});
                                 challengeHash = read_reg.execute(reg_index);
                             */

//                            reg_index = hash2.get({hdr.auth.uavIdentifier});
//                            challengeHashRecvd = read_reg.execute(reg_index);
                            //challengeHashRecvd = read_reg.execute(hdr.auth.uavIdentifier);
                            challenge_hash_reg.read(hdr.auth.uavIdentifier,challengeHashRecvd);
                            if(hdr.auth.randomNumber == challengeHashRecvd)
                            {
                                /*successfully authenticated */
                                hdr.auth.authMsgType = 3; //auth challenge message
                                hdr.auth.challenge1 = 0;
                                hdr.auth.challenge2 = 0;
                                hdr.auth.randomNumber = 0;

                        //        hdr.udp.udpChkSum=0;

                                send(standard_metadata.ingress_port);
                          /*      tmpMac = hdr.ethernet.destMac;
                                hdr.ethernet.destMac = hdr.ethernet.srcMac;
                                hdr.ethernet.srcMac = tmpMac;
                                tmp = hdr.ipv4.srcAddr;
                                hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                                hdr.ipv4.dstAddr = tmp;
                                tmpPort = hdr.udp.dstPort;
                                hdr.udp.dstPort = hdr.udp.srcPort;
                                hdr.udp.srcPort = tmpPort;
                                */

                            }
                            else
                            {
                                //authentication failed, drop the packet
                                drop();
                            }
                            
                        }
                    }
                    else //UAV not registered
                    {
                        drop();
                    }
                }

            }
        }
    }
}
/************************ EGRESS PROCESSING******************/
control MyEgress(inout ingress_headers_t hdr,
                    inout ingress_metadata_t meta,
                    inout standard_metadata_t standard_metadata){
                    apply{}
}
/*********************  D E P A R S E R  ************************/

control MYComputreChesksum(inout ingress_headers_t    hdr,
        inout    ingress_metadata_t   meta)
{
    //Checksum() ipv4_checksum;
    //Checksum()  l4_checksum;
    apply {
          if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum ({
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.totalLen,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.fragOffset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr
                });
        }

hdr.udp.udpChkSum({
                        hdr.ipv4.srcAddr,
                        hdr.ipv4.dstAddr,
                        8w0, hdr.ipv4.protocol,
                        hdr.udp.udpLen,
                        hdr.udp.srcPort,
                        hdr.udp.dstPort,
                        hdr.udp.udpLen,
                        hdr.auth.authMsgType,
                        hdr.auth.challenge1,
                        hdr.auth.challenge2,
                        hdr.auth.randomNumber,
                        hdr.auth.uavIdentifier
                    });

  
    }

}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


/*********************  D E P A R S E R  ************************/

control MyDeparser(packet_out packet, in ingress_headers_t hdr)
{
    apply {
        packet.emit(hdr);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.auth);
    }
}

/************ F I N A L   P A C K A G E ******************************/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MYComputreChesksum(),
    MyDeparser()
) main;



