    /* Mateusz Gembarzewski
     * Dr. Leune
     * Applied Cryptography 
     * Assignment #7
     *
     * Collaboration with Brian Reiskin, Mateusz Piekut, Andrew Viola
     */

    #include <iostream>
    #include <bitset>
    #include <algorithm>
    #include <sstream>
    #include <iomanip>
    
    using namespace std;

    const unsigned long box1[2][8]={
            {0b101, 0b010, 0b001, 0b110, 0b011, 0b100, 0b111, 0b000},
            {0b001, 0b100, 0b110, 0b010, 0b000, 0b111, 0b101, 0b011}
    };
    const unsigned long box2[2][8]={
            {0b100, 0b000, 0b110, 0b101, 0b111, 0b001, 0b011, 0b010},
            {0b101, 0b011, 0b000, 0b111, 0b110, 0b010, 0b001, 0b100}
    };

    /* implementation of simplified DES-Type algorithm expander function
     * on page 116.
     * each round takes 6 bits of input and produces 8 bits of output
     */
    unsigned long expand(unsigned long r) {
        unsigned long out= 0;
        bool j = 0;
        //first bit shift where we mask the bit and put the boolean result into the output stream
        j = (r & 0b100000) == 0b100000;
        out += 128*j;
        //next bitshift
        j = (r & 0b010000) == 0b010000;
        out += 64*j;
        //3rd bitshift special case have to take into account the fact that 3 goes in the 16 and 4 place
        j = (r & 0b001000) == 0b001000;
        out += 20*j;
        //4th bitshift is also special because putting the result into the 32 and 8 place
        j = (r & 0b000100) == 0b000100;
        out += 40*j;
        //5th and 6th bitshifts are single replacers like the first
        j = (r & 0b000010) == 0b000010;
        out += 2*j;
        j = (r & 0b000001) == 0b000001;
        out += 1*j;
        return out;

    }

    /* Apply substitution-box 'box' to input 's'
     * 's' is a four-bits input; function returns a 3-bits value
     */
    unsigned long sub(const unsigned long box[][8], unsigned long s) {
        unsigned long out;
        bool first;
        unsigned long pos;
        first = (s&0b1000) == 0b1000;
        pos = (s&0b0111);
        out = box[first][pos];
        //cout << bitset<3>(out);
        return out;

    }

    /* Execute the f-function on r, using subkey k
     * r is a 6-bits value; k is an b-bits subkey. Returns a 6-bits value
     */
    unsigned long f(unsigned long r, unsigned long k) {
        unsigned long out =expand(r);
        out = out ^ k;
        unsigned long s1 = (out&0b11110000) >> 4;
        unsigned long s2 = out&0b00001111;
        s1 =sub(box1,s1);
        s2 =sub(box2,s2);
        out = (s1<<3)|s2;
        return out;
    }

    /* Returns an 8-bits subkey, derived from an 9-bits input key */
    unsigned long subkey(unsigned long key, unsigned int n) {

        for (int i=0; i < n-1; i++) {
            if ((key & 0b100000000) == 0b100000000)
                key = (key << 1) | 1;
            else
                key = key << 1;
        }

        return (key >> 1) & 0b11111111;
    }

    /* perform one round of encryption */
    unsigned long round(unsigned long in, unsigned long key, unsigned int round) {
        unsigned long out=0;
        unsigned long l =(in&0b111111000000)>>6;
        unsigned long r =(in&0b000000111111);
        unsigned long r2 =r;
        out = r<<6 | l^f(r2,subkey(key,round));

        //out =(f(l,subkey(key,round))<<6)^f(r,subkey(key,round));
        return out;
    }
    
    //Helper function that takes in a string and returns binary representation (long)
    unsigned long str2long(string in){
        //bin will hold the binary value, will have chars incrementallity added as bits. 
        unsigned long bin = 0;
        //each char is 8 bits, for each char in parameter 'in' 8 bits added
        for (char s : in) {
            //bitset<8> defines a size of 8-bits 
            bin += bitset<8>(s).to_ulong(); //for every char in 'in' the char's binary value added into bin
            bin = bin <<8; //bitwise left shift 8 positions over to the left, adds room for next char
                           // example: 0000000011111111 << 8 = 1111111100000000, ready for next char
        }
        
        bin = bin >>8; //moves the current bin values over 8 places to the right
                       //removes the excess 8 zeros left by the last instance of for loop  
        return bin;
    }
    
    string longtohex(unsigned long in) {
        stringstream out;
        out << hex << setfill('0') << setw(8) << in;
        return out.str();
    }
    
    /* Now that we have string as binary value, we can pass into ECB()
     * Will break the 48 bit long into 4 blocks, applying the key with DES-like cipher 
     * to form encrypted blocks, which joined to form whole cyphertext
     *
     *
     */
    unsigned long ECB(unsigned long key, unsigned long plain){
        string bin = bitset<48>(plain).to_string(); //retuns string representation of 48 bit unsigned long plain
        int totalBlocks = bin.size()/12; //represents the 4 total blocks - total bits (48) divided by blocksize (12)
        
        unsigned long currentBlock = 0; //the block being opereated on for each iteration
        unsigned long shift = 0; //shift
        unsigned long result = 0; //sum
        int k = 0; //counter

        for(k = 1; k <= totalBlocks; k++){
            
            shift = 12*(k-1); //for every encrypted block made we have to create 12 more bit spaces for the next encryption
            
            currentBlock = (plain << shift); //1st block shift 0 to left, 2nd block 12, 3rd block 24, 4th block 36

            currentBlock = (currentBlock >> 36); //moves the current block into the correct bit position

            result += round(currentBlock, key, 1); //performs 1 round of DES-like encryption on currentBLock with key

            result = result << 12; // each block added to the result and pushed 12 to the left making room for next block
        }

        return result = result >> 12; //removes the extra zeros by shift back over 12 to the right

    }
    
    unsigned long CBC(unsigned long iv, unsigned long plain, unsigned long key){
        string bin = bitset<48>(plain).to_string();
        int totalBlocks = bin.size()/12;

        unsigned long blockX = 0; //currentBLock being worked on
        unsigned long shift = 0; //shift
        unsigned long result = 0; //sum
        int k = 0; //counter

        for(k = 1; k <= totalBlocks; k++) {
            shift = 12*(k-1);
            blockX = (plain << shift);
            blockX = (blockX >> 36);
            //cout<< "before blockX round: "<< k<<"  "<<bitset<48>(blockX)<<endl;
            blockX = iv ^ blockX; //XOR bit operation between IV and currentBlock
            //cout<< "after blockX round: "<<k<<"  "<<bitset<48>(blockX)<<endl;
            iv = round(blockX, key, 1); //gets next IV for next round of encryptiom

            result += round(blockX, key, 1);
            //newiv = result;
            //cout<< "iv: "<<bitset<48>(iv)<<endl;
            result = result << 12;
        }

        result = result >> 12;
        return result;
    }
    /* the driver function. Do not make changes to this */
    int main() {
        string w="World!"; 
        unsigned long plain = str2long(w); //takes in string and chamges to binary representation
        unsigned long key   = 0b110100101; // 421 = key
        unsigned long initializationVector=0b1111100;// 124 = initialization Vector (iv)

        //unsigned long cipher = round(plain, key, 4);
        //call longtohex to get hexadecimal representation
        cout<< "EBC: "<<longtohex(ECB(key,plain))<<endl;
        cout<< "CBC: "<<longtohex(CBC(initializationVector,plain,key));

    }

