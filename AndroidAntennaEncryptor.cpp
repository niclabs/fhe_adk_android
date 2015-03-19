#include "EncryptedArray.h"
#include <fstream>
#include <iostream>
#include <string>     
#include <sstream>
#include <map>
#include <time.h>

/*
AntennaEncryptor
Object that handles the encryption of antennas.

Initializes pk, context and antenna hash from files.
Encrypts an antenna identifier.
Stores the encryption in a file.
*/

#define CTXT_FILE "result_cipher"
#define CONTEXT_FILE "/data/local/tmp/context"
#define PUBLIC_KEY_FILE "/data/local/tmp/key.pub"
#define HASH_1_FILE "/data/local/tmp/a_1_hash"
#define HASH_2_FILE "/data/local/tmp/a_2_hash"
#define DEBUG 1


class AntennaEncryptor{
  
  FHEcontext context;
  FHEPubKey public_key;
  ZZX G;
  EncryptedArray encrypted_array;
  std::map< string, string > antenna_hash;

FHEcontext InitializeContext(){
  std::cout << "initializing context..." << std::endl;
  fstream context_file;
  context_file.open(CONTEXT_FILE, fstream::in);
  unsigned long m1, p1, r1;
  readContextBase(context_file, m1, p1, r1);
  FHEcontext context_(m1, p1, r1);

  context_file >> context_;//Be sure to generate the context file in 32 bits.
  context_file.close();
  std::cout << "done" << std::endl;
  
  return context_;
}

FHEPubKey InitializePk(){
  std::cout << "initializing pk..." << std::endl;
  fstream pk_file;
  pk_file.open (PUBLIC_KEY_FILE);
  FHEPubKey p_key(this->context);
  pk_file >> p_key;
  pk_file.close();
  std::cout << "done" << std::endl;

  return p_key;
}
EncryptedArray InitializeEncryptedArray(){
  std::cout << "initializing encrypted array..." << std::endl;
  this->G = this->context.alMod.getFactorsOverZZ()[0];
  EncryptedArray encrypted_array_(this->context, this->G);
  std::cout << "done" << std::endl;
  return encrypted_array_;
}
void InitializeHash(int mnc_){
  std::cout << "initializing hash..." << std::endl;
  string hash_mnc[3] = {"",HASH_1_FILE, HASH_2_FILE } ;

  std::ifstream hash_file(hash_mnc[mnc_].c_str());
  string mnc, lac, cid, a,z,pz, key;
  while (hash_file >> mnc >> lac >> cid >> a >> z >> pz)
  {
    key = lac + " " + cid;
    this->antenna_hash[key] = a + " " + z + " " + pz;
  }
  std::cout << "done" << std::endl;
}

vector<long> BuildVector(int code, int encrypted_array_size){
  //code starts in 1 / vector starts in 0. code<= encrypted_array_size
  vector<long> code_vector;
  for(int i = 0 ; i < code-1; i++)
    code_vector.push_back(0);
  code_vector.push_back(1);

  for(int i = code ; i < encrypted_array_size; i++)
    code_vector.push_back(0);

  return code_vector;
}

public:
  AntennaEncryptor(int mnc):
    context(InitializeContext()), public_key(InitializePk()), encrypted_array(InitializeEncryptedArray())
    {
      InitializeHash(mnc);
    }
  
  FHEcontext get_context(){
    return context;
  }
  FHEPubKey get_public_key(){
    return public_key;
  }
  EncryptedArray get_encrypted_array(){
    return encrypted_array;
  }
  std::map< string, string > get_antenna_hash(){
    return antenna_hash;
  }
  int get_antenna_code(int lac, int cid){
  
    int a_code, z_code, pz_code;
    stringstream lac_cid;
    lac_cid << lac << " " << cid;
    string in_code = lac_cid.str();
    string out_code = antenna_hash[in_code];
    stringstream ss_lac_cid(out_code);
    
    while(ss_lac_cid >> a_code >> z_code >> pz_code) {
      return a_code;
    }
    return 0;
      
  }
  int get_zone_code(int lac, int cid){

    int a_code, z_code, pz_code;
    stringstream lac_cid;
    lac_cid << lac << " " << cid;
    string in_code = lac_cid.str();
    string out_code = antenna_hash[in_code];
    stringstream ss_lac_cid(out_code);
    
    while(ss_lac_cid >> a_code >> z_code >> pz_code) {
      return z_code;
    }
    return 0;
  }
  int get_pzone_code(int lac, int cid){

    int a_code, z_code, pz_code;
    stringstream lac_cid;
    lac_cid << lac << " " << cid;
    string in_code = lac_cid.str();
    string out_code = antenna_hash[in_code];
    stringstream ss_lac_cid(out_code);
    
    while(ss_lac_cid >> a_code >> z_code >> pz_code) {
      return pz_code;
    }
    return 0;
  }
  
  Ctxt EncryptAntenna(int lac, int cid){
    if (DEBUG > 0) cerr << "encrypting: " << lac << " " << cid << endl;
    
    int antenna_code = get_antenna_code(lac,cid);
    int zone_code = get_zone_code(lac,cid);
    if (DEBUG > 0)
      cerr << antenna_code << " " << zone_code << endl;

    Ctxt antenna_cipher(this->public_key);
    PlaintextArray antenna_plaintext(this->encrypted_array);

    if(antenna_code == 0 && zone_code==0){
      //Nothing to encrypt
      throw 33;
    }

    std::vector<long> antenna_vector = BuildVector(antenna_code, this->encrypted_array.size());
    
    antenna_plaintext.encode(antenna_vector);
    this->encrypted_array.encrypt(antenna_cipher, this->public_key, antenna_plaintext);
    
    return antenna_cipher;

  }
  Ctxt EncryptZone(int lac, int cid){
    if (DEBUG > 1) cerr << "encrypting: " << lac << " " << cid << endl;
    
    int antenna_code = get_antenna_code(lac,cid);
    int zone_code = get_zone_code(lac,cid);
    if (DEBUG > 1)
      cerr << antenna_code << " " << zone_code << endl;

    Ctxt zone_cipher(this->public_key);
    PlaintextArray zone_plaintext(this->encrypted_array);

   
    if(antenna_code == 0 && zone_code==0){
      //Nothing to encrypt
      throw 33;
    }
    
    std::vector<long> zone_vector = BuildVector(zone_code, this->encrypted_array.size());
    
    zone_plaintext.encode(zone_vector);
    this->encrypted_array.encrypt(zone_cipher, this->public_key, zone_plaintext);
    
    return zone_cipher;

  }
  Ctxt CtxtFromString(string cipher_string){
    Ctxt cipher(public_key);
    stringstream ss_cipher;
    ss_cipher << cipher_string;
    ss_cipher >> cipher;
    return cipher; 
  }
  void CtxtToFile(Ctxt cipher){
    ofstream cipher_file;
    cipher_file.open(CTXT_FILE);
    cipher_file << cipher ;
    cipher_file.close();

  }
};

int main(int argc, char const *argv[]){
  /*
    Encrypts 100 antennas on Android device. Measures the execution time.
  */
  int mnc = 1;
  clock_t t1, t2;
  double dt;
  //int  a_id[2][2] = {{13502, 86562093},{13002, 53851}};

  

  int  a_id[100][2] = {{13502, 86562093},
{13002, 53851},
{13507, 85679825},
{13610, 86564693},
{13502, 85826996},
{13002, 22761},
{13613, 86106175},
{13507, 86560642},
{13612, 85987625},
{13620, 86600148},
{13630, 86594543},
{13516, 85616782},
{13610, 86514903},
{13516, 85646117},
{13630, 86069536},
{13509, 85807415},
{13509, 85812268},
{13502, 85815007},
{13502, 85843940},
{13612, 86007704},
{13610, 86552253},
{13517, 85679744},
{5506, 33309695},
{13610, 86534277},
{13613, 86618180},
{13004, 21963},
{13502, 85812645},
{13610, 86567119},
{13611, 85970907},
{13611, 85939580},
{13630, 86075270},
{13630, 86107442},
{13527, 85675661},
{13614, 86172272},
{13007, 20773},
{13506, 85646339},
{13610, 86527709},
{13517, 85682095},
{13613, 86069754},
{13610, 86528473},
{13620, 86107151},
{13527, 85677820},
{13507, 85664685},
{31306, 85617418},
{13620, 86617962},
{13612, 86660115},
{13612, 85987435},
{13507, 85683888}, 
{13611, 59182},
{13509, 85807992},
{13620, 86103526},
{13613, 86624391},
{13011, 25471},
{13620, 86106954},
{13630, 86069737},
{13008, 40053},
{13004, 54331},
{13630, 86107239},
{13004, 54332},
{13613, 86070714},
{13507, 85682424},
{13509, 85807571},
{31306, 85616940},
{5504, 33005534},
{13502, 85814518},
{13507, 85657918},
{13008, 51531},
{13614, 86115865},
{13007, 10830},
{5007, 20481},
{13507, 85707089},
{13620, 86075271},
{30506, 33349344},
{13620, 86106999},
{13516, 85644700},
{13610, 85814009},
{13630, 85706956},
{13516, 85610383},
{13527, 85696524},
{13509, 85815000},
{13614, 86172375},
{13620, 86103519},
{13614, 86142249},
{13630, 86107264},
{13502, 85808020},
{13507, 86547984},
{13516, 85614655},
{2317, 36792},
{13502, 85843938},
{13517, 85683979},
{13516, 86567069},
{5514, 33205917},
{13620, 86106562},
{5007, 27552},
{13620, 86049181},
{5514, 33188767},
{13509, 85843916},
{13516, 85646210},
{13620, 86597217},
{13527, 85677198}};

  std::cout << "initializing..." << std::endl;
  t1 = clock();
  AntennaEncryptor antenna_encryptor(mnc);
  t2 = clock();
  dt = (double) (t2-t1) / CLOCKS_PER_SEC * 1000.0;
  std::cerr << dt << " ms" << endl;
  

  std::cout << "Done." << std::endl;
  for(int i=0; i<100; i++){
    try{
      t1 = clock();
      antenna_encryptor.EncryptAntenna(a_id[i][0], a_id[i][1]);
      t2 = clock();
      dt = (double) (t2-t1) / CLOCKS_PER_SEC * 1000.0;
      std::cerr << dt << " ms." << endl;
    }catch (int e){
      std::cerr << "antenna not found" << endl;
      continue;
    }
  }

  std::cout << "Done." << std::endl;

  

  return 0;
}

