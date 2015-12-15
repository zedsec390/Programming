##
# Uncomplete porting / modification of amblist mvs program to python
# Currently not all records are parsed entirely.
# Also, the functinality as is works only on Load Modules, not 
# program objects or GOFF formats.
# As is, it will generate hex output that will match the TXT sections
# of the AMBLIST LISTLOAD and build an internal data structre (a bunch
# of dictionaries for now) that map most (not yet all) of the records
##
import os,sys
from struct import pack,unpack


class LoadModule:
    """ Main LoadModule Class """
    lm_size = 0           # size of the entire load module
    lm_binary = ''        # binary bytes of entire  lm
    lm_init = False       # are we initialized
    lm_parsed = False     # have we parsed records
    lm_records = []       # individual records
    lm_recnum = 1         # record #
    DEBUG = 0             # one for verbose debug; 0 none

    def loadBinary(self, binary):
        """ loads the binary LM object so we can do further processing """
        lb_size = 0
        lb_binary = ''
        try:
            f1=open(binary,'rb')
            lb_binary = f1.read()
            lb_size = len(lb_binary)
            f1.close()
        except Exception as e:
            raise e
        self.lm_size = lb_size
        self.lm_binary = lb_binary
        self.lm_init = True
        self.lm_parsed = False
        self.dprint("loadBinary {0:d} bytes loaded.".format(lb_size))
        return True

    def parse(self):
        """ parses the binary into individual records. Returns nothing  """
        if ((self.lm_parsed == True) or (self.lm_init == False)):   # can only call parse 1x per object
            raise Exception("Cannot call parse more than once per object.")

        # while loop variables
        p_size = self.lm_size
        offs = 0

        # parse load module and store records
        while offs < p_size:
            byte1 = self.lm_binary[offs]   # read identification byte
            tmp = ''                       # receive tmp record
            rlen = 0                       # record length
            process_text_rec = False       # set to true to triger text (binary) rec process

            if byte1 == '\x01':            # record type 01
                (tmp,rlen) = self.__load01(offs)
            #   self.dprint("received {0:s} rlen {1:d}".format(tmp,rlen))
                process_text_rec = True
            elif byte1 == '\x02':          # record type 02
                # for type 02 process control record then text record
                (tmp,rlen) = self.__load02(offs)
            #   self.dprint("received {0:s} rlen {1:d}".format(tmp,rlen))
            elif byte1 == '\x03':         # record type 03
                (tmp,rlen) = self.__load03(offs)
            #   self.dprint("received {0:s} rlen {1:d}".format(tmp,rlen))
                process_text_rec = True
            elif byte1 == '\x0E':          # record type 0E
                # for type 0E process control record then text record
                (tmp,rlen) = self.__load0E(offs)
            #   self.dprint("received {0:s} rlen {1:d}".format(tmp,rlen))
            elif byte1 == '\x0F':         # record type 0F
                (tmp,rlen) = self.__load0F(offs)
                process_text_rec = True
            elif byte1 == '\x20':          # record type 20
                (tmp,rlen) = self.__load20(offs)
                #self.dprint("received {0:s} rlen {1:d}".format(tmp,rlen))
            elif byte1 == '\x80':          # record type 80
                (tmp,rlen) = self.__load80(offs)
                #self.dprint("received {0:s} rlen {1:d}".format(tmp,rlen))
            else:                          # some other record, we crash n' burn
                raise Exception("Record type {0:s} not found at offset {1:d}. Exiting.".format(byte1.encode('hex'),offs))
            # end if
           
            # add the record 
            offs = self.__addRec(tmp,offs,rlen)

            # do we need to process a txt record?
            if process_text_rec == True:
                recs = tmp['size']/4
                recData = tmp['rec_data']
                self.dprint("TXT:process_text_rec recs={0:d}, recData={1:s}".format(recs,recData))
                txtLen = 0
                for ir in recData.keys():             # loop through cesd records
                    txtLen = txtLen + recData[ir]
                (tmp,rlen) = self.__loadTXT(offs, txtLen)
#               self.dprint("TXT:received {0:s} rlen {1:d}".format(tmp,rlen))
                # add the record 
                offs = self.__addRec(tmp,offs,rlen)
                process_text_rec = False

            # end while loop
    # end parse()

    def __loadTXT(self, offset, txtLen):
        """  Process a txt (binary) record """
        self.dprint("rec {0:d} type:recTXT offs {1:d}".format(self.lm_recnum,offset))
        txt_data = self.lm_binary[offset:offset+txtLen]
        txt_record = {
            'recNum':self.lm_recnum,
            'txtData':txt_data
            }
        return(txt_record,txtLen)

    def __addRec(self,tmp,offs,rlen):
        """ Add a record to the global record buffer """
        self.lm_records.append(tmp)
        self.lm_recnum += 1
        self.lm_parsed = True
        offs = offs + rlen
        return offs
    # end addRec()

    def __load01(self,offset):
        """ Private method laods type 01 Control Record described below
            expects offset of binary loaded into class passed as parameter
        """
        self.dprint("rec {0:d} type:rec01 offs {1:d}".format(self.lm_recnum,offset))
        # double check we got a good offset
        if self.lm_binary[offset] != '\x01':
            raise Exception("No record 01 found at offset {0:d}".format(offset))

        # parse the header and data
        r01_ctlrec_count = unpack('>B',self.lm_binary[offset+3:offset+4])[0] # ct of ctl records 
        r01_byte_count = unpack('>h',self.lm_binary[offset+4:offset+6])[0]   # total bytes of data
        r01_ccw = self.lm_binary[offset+8:offset+16]                         # ccw
        r01_ctl_data = self.lm_binary[offset+16:offset+16+r01_byte_count]    # binary data of rec
        r01_tmp = {}
        for r1 in range(0, r01_byte_count, 4):
            entryNum = unpack('>h',r01_ctl_data[r1+0:r1+2])[0]  # of esd entry
            txtLen = unpack('>h',r01_ctl_data[r1+2:r1+4])[0]    # len of txt entry
            r01_tmp[entryNum] = txtLen                    # add entry
    
        r01_record = {
            'recNum':self.lm_recnum,
            'rec_count':r01_ctlrec_count,
            'size':r01_byte_count,
            'ccw':r01_ccw,
            'rec_data':r01_tmp
            }
        tlen = 16 + r01_byte_count   # total length of record for counter
        return (r01_record,tlen)
    ## end __load01

    def __load02(self,offset):
        """ Private method laods type 02 CESD Record described below """
        self.dprint("rec {0:d} type:rec02 offs {1:d}".format(self.lm_recnum,offset))
        # double check we got a good offset
        if self.lm_binary[offset] != '\x02':
            raise Exception("No record 02 found at offset {0:d}".format(offset))

        # parse the header and data
        r02_rldrec_count = unpack('>B',self.lm_binary[offset+3:offset+4])[0] # ct of rld records 
        r02_byte_count = unpack('>h',self.lm_binary[offset+6:offset+8])[0]   # total bytes of data
        r02_rld_data = self.lm_binary[offset+16:offset+16+r02_byte_count]    # binary data of rec
        r02_record = {
            'recNum':self.lm_recnum,
            'rec_count':r02_rldrec_count,
            'size':r02_byte_count,
            'rec_data':r02_rld_data
            }
        tlen = 16 + r02_byte_count   # total length of record for counter
        return (r02_record,tlen)
    ## end __load02

    def __load03(self,offset):
        """ Private method laods type 03 CESD Record described below
            expects offset of binary loaded into class passed as parameter
        """
        self.dprint("rec {0:d} type:rec03 offs {1:d}".format(self.lm_recnum,offset))
        # double check we got a good offset
        if self.lm_binary[offset] != '\x03':
            raise Exception("No record 03 found at offset {0:d}".format(offset))

        # parse the header and data
        r03_ctl_count = unpack('>h',self.lm_binary[offset+4:offset+6])[0] # ct of ctl records 
        r03_rld_count = unpack('>h',self.lm_binary[offset+6:offset+8])[0] # ct of ctl records 
        r03_ccw = self.lm_binary[offset+8:offset+16]                      # ccw
        r03_rld_data = self.lm_binary[offset+16:offset+16+r03_rld_count]  # binary data of rec
        r03_ctl_data = self.lm_binary[offset+16+r03_rld_count:offset+16+r03_rld_count+r03_ctl_count]  # binary data of rec
        r03_tmp = {}
        for r1 in range(0, r03_ctl_count, 4):
            entryNum = unpack('>h',r03_ctl_data[r1+0:r1+2])[0]  # of esd entry
            txtLen = unpack('>h',r03_ctl_data[r1+2:r1+4])[0]    # len of txt entry
            r03_tmp[entryNum] = txtLen                          # add entry
    
        r03_record = {
            'recNum':self.lm_recnum,
            'size':r03_ctl_count,
            'rld_size':r03_rld_count,
            'ccw':r03_ccw,
            'rec_data':r03_tmp,
            'rld_data':r03_rld_data
            }
        tlen = 16 + r03_ctl_count + r03_rld_count     # total length of record for counter
        return (r03_record,tlen)
    ## end __load03

    def __load0E(self,offset):
        """ Private method laods type 0E CESD Record described below """
        self.dprint("rec {0:d} type:rec0E offs {1:d}".format(self.lm_recnum,offset))
        # double check we got a good offset
        if self.lm_binary[offset] != '\x0E':
            raise Exception("No record 0E found at offset {0:d}".format(offset))

        # parse the header and data
        r0E_rldrec_count = unpack('>B',self.lm_binary[offset+3:offset+4])[0] # ct of rld records 
        r0E_byte_count = unpack('>h',self.lm_binary[offset+6:offset+8])[0]   # total bytes of data
        r0E_rld_data = self.lm_binary[offset+16:offset+16+r0E_byte_count]    # binary data of rec
        r0E_record = {
            'recNum':self.lm_recnum,
            'rec_count':r0E_rldrec_count,
            'size':r0E_byte_count,
            'rec_data':r0E_rld_data
            }
        tlen = 16 + r0E_byte_count   # total length of record for counter
        return (r0E_record,tlen)
    ## end __load0E

    def __load0F(self,offset):
        """ Private method laods type 0F CESD Record described below
            expects offset of binary loaded into class passed as parameter
        """
        self.dprint("rec {0:d} type:rec0F offs {1:d}".format(self.lm_recnum,offset))
        # double check we got a good offset
        if self.lm_binary[offset] != '\x0F':
            raise Exception("No record 0F found at offset {0:d}".format(offset))

        # parse the header and data
        r0F_ctl_count = unpack('>h',self.lm_binary[offset+4:offset+6])[0] # ct of ctl records 
        r0F_rld_count = unpack('>h',self.lm_binary[offset+6:offset+8])[0] # ct of ctl records 
        r0F_ccw = self.lm_binary[offset+8:offset+16]                      # ccw
        r0F_rld_data = self.lm_binary[offset+16:offset+16+r0F_rld_count]  # binary data of rec
        r0F_ctl_data = self.lm_binary[offset+16+r0F_rld_count:offset+16+r0F_rld_count+r0F_ctl_count]  # binary data of rec
        r0F_tmp = {}
        for r1 in range(0, r0F_ctl_count, 4):
            entryNum = unpack('>h',r0F_ctl_data[r1+0:r1+2])[0]  # of esd entry
            txtLen = unpack('>h',r0F_ctl_data[r1+2:r1+4])[0]    # len of txt entry
            r0F_tmp[entryNum] = txtLen                          # add entry
    
        r0F_record = {
            'recNum':self.lm_recnum,
            'size':r0F_ctl_count,
            'rld_size':r0F_rld_count,
            'ccw':r0F_ccw,
            'rec_data':r0F_tmp,
            'rld_data':r0F_rld_data
            }
        tlen = 16 + r0F_ctl_count + r0F_rld_count     # total length of record for counter
        return (r0F_record,tlen)
    ## end __load0F

    def __load20(self,offset):
        """ Private method laods type 20 CESD Record described below
            expects offset of binary loaded into class passed as parameter
        """
        self.dprint("rec {0:d} type:rec20 offs {1:d}".format(self.lm_recnum,offset))
        # double check we got a good offset
        if self.lm_binary[offset] != '\x20':
            raise Exception("No record 20 found at offset {0:d}".format(offset))

        # parse the header and data
        r20_flag = self.lm_binary[offset+1:offset+2]                         # either 00 or 80
        r20_first_esdid = unpack('>h',self.lm_binary[offset+4:offset+6])[0]  # beginning esd
        r20_byte_count = unpack('>h',self.lm_binary[offset+6:offset+8])[0]   # total bytes of data
        r20_data = self.lm_binary[offset+8:offset+8+r20_byte_count]          # binary data of rec
        r20_record = {
            'recNum':self.lm_recnum,
            'flag':r20_flag,
            'esdid':r20_first_esdid,
            'size':r20_byte_count,
            'esd_data':r20_data
            }
        tlen = 8 + r20_byte_count   # total length of record for counter
        return (r20_record,tlen)
    ## end __load20

    def __load80(self,offset):
        """ Private method laods type 80 CESD Record described below
            expects offset of binary loaded into class passed as parameter
        """
        self.dprint("rec {0:d} type:rec80 offs {1:d}".format(self.lm_recnum,offset))

        # double check we got a good offset
        if self.lm_binary[offset] != '\x80':
            raise Exception("No record 80 found at offset {0:d}".format(offset))

        # parse the header and data
        r80_byte_count = unpack('>B',self.lm_binary[offset+1:offset+2])[0]-2  # total bytes of data, incl this one
        r80_subtype = self.lm_binary[offset+2:offset+3]                       # sub-type cesd
        r80_data = self.lm_binary[offset+3:offset+3+r80_byte_count]           # binary data of rec
        r80_record = {
            'recNum':self.lm_recnum,
            'subtype':r80_subtype,
            'size':r80_byte_count,
            'esd_data':r80_data
            }
        tlen = 3 + r80_byte_count   # total length of record for counter
        return (r80_record,tlen)
    ## end __load80

    ## public utility functions
    def getSize(self):
        """ returns full size of LM binary """
        if self.lm_init:
            return self.lm_size
        else:
            return 0          # error

    def getRecords(self):
        """ returns raw bytes of LM binary """
        if ((self.lm_parsed == False) and (self.lm_init == False)):
            return 0          # error
        else:
            return self.lm_records

    def getRecCount(self):
        """ returns raw bytes of LM binary """
        if ((self.lm_parsed == False) and (self.lm_init == False)):
            return 0          # error
        else:
            return self.lm_recnum

    def getRaw(self):
        """ returns raw bytes of LM binary """
        if self.lm_init:
            return self.lm_binary
        else:
            return 0

    def dprint(self,val):
        """ Debug printer """
        if self.DEBUG:
            print ("Debug: {0:s}".format(val))
##
## end Class LoadModule
##


row=0
def hexPrint(data):
    global row
    col=0
    b=0
    for i in data:
        if col % 32 == 0:
            sys.stdout.write("\n")
            col = 0
            sys.stdout.write(" {0:06X}    ".format(row))
        x = unpack('>B',i)[0]
        sys.stdout.write("{0:02X}".format(x))
        row += 1
        col += 1
        if col % 4 == 0:
            sys.stdout.write(" ")
    print("")

if __name__=="__main__":
    if len(sys.argv) > 1:
        fileName = sys.argv[1]
    else:
        print("Usage: <pgm.py> <filename>")
        sys.exit(1)
    lm = LoadModule()
    lm.dprint("Using file: {0:s}".format(fileName))
    lm.loadBinary(fileName)
    lm.parse()
    r = lm.getRecords()
    for i in r:
        if 'txtData' in i:
            hexPrint(i['txtData'])
