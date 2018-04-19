#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <sstream>
#include <thread>
#include <cmath>
#include <vector>
#include <chrono>
#include <utility>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <algorithm>
#include <pqxx/pqxx>
#include <cctype>

using namespace std;

string md5(string str){
	const unsigned char * constStr = reinterpret_cast<const unsigned char *> (str.c_str());
	unsigned char strHash[MD5_DIGEST_LENGTH];
	
	MD5(constStr, str.length(), strHash);
	
	// Convert to hexadecimal representation (taken from https://stackoverflow.com/a/27946306/6061951)
	stringstream buffer;
	for(short i = 0; i<MD5_DIGEST_LENGTH; i++){
		buffer << std::hex << std::setfill('0');
		buffer << std::setw(2) << static_cast<unsigned>(strHash[i]);
	}
	return buffer.str();
}

string sha1(string str){
	const unsigned char * constStr = reinterpret_cast<const unsigned char *> (str.c_str());
	unsigned char strHash[SHA_DIGEST_LENGTH];
	
	SHA1(constStr, str.length(), strHash);
	
	// Convert to hexadecimal representation (taken from https://stackoverflow.com/a/27946306/6061951)
	stringstream buffer;
	for(short i = 0; i<SHA_DIGEST_LENGTH; i++){
		buffer << std::hex << std::setfill('0');
		buffer << std::setw(2) << static_cast<unsigned>(strHash[i]);
	}
	return buffer.str();
}

bool isGood(string str){
	for(unsigned i=0; i<str.length(); i++){
		if(str[i] == '\'' || str[i] == '"' || !isprint(str[i]))
			return false;
	}
	return true;
}

void addHashDB(vector<pair<string, string> > toAdd){
	using namespace pqxx;
	try {
		pqxx::connection DB("dbname = testdb user = postgres password = qwsxdcfv7 hostaddr = 127.0.0.1 port = 5432");
		
		/* Create SQL statement */
		stringstream ss;
		for(unsigned i=0; i<toAdd.size(); i++){
			if(isGood(toAdd[i].first) && isGood(toAdd[i].second))
				ss << "INSERT INTO bruteforce (pwd,hash) VALUES ('" << toAdd[i].first << "','" << toAdd[i].second << "');";
		}
		
		work W(DB);
		W.exec(ss.str());
		W.commit();
		
		DB.disconnect();
	} catch (const exception &e){
		cerr << e.what() << endl;
	}
}

string queryDB(string hash){
	using namespace pqxx;
	try{
		static pqxx::connection DB("dbname = testdb user = postgres password = qwsxdcfv7 hostaddr = 127.0.0.1 port = 5432");
		
		if(!DB.is_open()){
			return "\nFail";
		}

		/* Create SQL statement */
		stringstream ss;
		if(!isGood(hash))
			return "\nFail";
		ss << "SELECT pwd,hash from bruteforce WHERE hash = '" << hash << "';";
		//const char* sql = ss.str().c_str();

		 /* Create a non-transactional object. */
		nontransaction N(DB);
		  
		  /* Execute SQL query */
		result R( N.exec( ss.str() ));
		  
		string pwd("\nFail");
		  /* List down all the records */
		for (result::const_iterator c = R.begin(); c != R.end(); ++c) {
			pwd = c[0].as<string>();
			break;
		}
		
		N.abort();
		
		/* Create a transactional object. */
		work W(DB);
		/* Create  SQL UPDATE statement */
		ss.clear();
		ss << "UPDATE bruteforce SET used = used + 1 WHERE hash='" << hash << "';";
		//sql = ss.str().c_str();
		
		/* Execute SQL query */
		W.exec( ss.str() );
		W.commit();
		
		DB.disconnect();
		
		return pwd;
	} catch (const exception &e){
		cerr << e.what() << endl;
		return "\nFail";
	}
	return "\nFail";
}

bool isPrintable(string str){
	for(unsigned i = 0; i<str.length(); i++){
		if(!isprint(str[i]))
			return false;
	}
	return true;
}

string bruteForce(int n, string hash){
	volatile bool flag = false;
	unsigned long max = pow(16, n*2);
	unsigned long min = 1;//pow(16, n*2-2)+1;
	string result("Error : not found.");
	vector<pair<string, string> > addToDB;
	//#pragma omp parallel for shared(flag)
	for(unsigned long permut = min; permut < max; permut++){
		if(flag) break;
		string hex;
		string passwd;
		stringstream buffer;
		buffer << std::hex << std::setfill('0');
		buffer << std::setw(n*2) << permut;
		hex = buffer.str();
		//cout << "\t" << hex << endl;
		for(int i=0; i<n*2; i+=2){
			string bte = hex.substr(i, 2);
			char chr = (char) (int)strtol(bte.c_str(), NULL, 16);
			//cout << "\t\t" << chr << endl;
			passwd.push_back(chr);
		}
		string test = sha1(passwd);
		
		// Add to database !
		if(addToDB.size() > 1000){
			addHashDB(addToDB);
			addToDB.clear();
		}
		if(addToDB.size() <= 1000){
			addToDB.push_back(pair<string, string>(passwd, test));
		}
		
		if(test.compare(hash) == 0){
			result = passwd;
			flag = true;
		}
	}
	addHashDB(addToDB);
	return result;
}

int main(int argc, char **argv)
{
	string psdHash;
	int n_letters;
	cout << "Enter hash of password : " << flush;
	cin >> psdHash;
	cin.get();
	
	cout << "Enter password length : " << flush;
	cin >> n_letters;
	if(isnan(n_letters) || n_letters == 0 || n_letters >= 6)
		return 1;
	
	string result;
	auto t0 = chrono::high_resolution_clock::now();
	result = queryDB(psdHash);
	if(result.compare("\nFail") == 0){
		cout << "Not found in database ! Brute forcing (may take a VERY long time - up to HUNDREDS of YEARS) !" << endl;
		cout << "Processing... " << flush;
		result = bruteForce(n_letters, psdHash);
		cout << "done !" << endl;
	}
	auto tf = chrono::high_resolution_clock::now();
	chrono::duration<double, std::milli> dt = tf-t0;

	cout << "Password is : " << result << endl;
	cout << "Time : " << dt.count() << " ms";
	cin.get();
	cin.get();
	return 0;
}
