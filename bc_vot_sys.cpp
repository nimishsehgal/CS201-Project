#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <map>
#include <algorithm>

using namespace std;

// structure to represent a block
struct Block
{
    int index;
    time_t timestamp;
    vector<string> votes;
    string previousHash;
    string merkleRoot;
    string hash;

    // constructor to initialize the block
    Block(int index, vector<string> votes, string previousHash)
    {
        this->index = index;
        this->timestamp = time(nullptr);
        this->votes = votes;
        this->previousHash = previousHash;
        this->merkleRoot = calculateMerkleRoot();
        this->hash = calculateHash();
    }

    // calculate the hash of the block
    string calculateHash()
    {
        string data = to_string(index) + to_string(timestamp) + previousHash + merkleRoot;
        unsigned char hash[SHA256_DIGEST_LENGTH]; // array of length 32, the standard hash length
        // convert the data string into a pointer of unsigned characters,
        // calculate its SHA-256 hash and store it in the hash array
        SHA256((unsigned char *)data.c_str(), data.length(), hash);
        // convert the resultant hash into hexadecimal and store it in hashStr
        string hashStr = "";
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            char hex[3];
            // convert a single byte of the hash into a two-character hexadecimal representation and store it in the hex array
            snprintf(hex, 3, "%02x", hash[i]);
            // append the hexadecimal representation to the string
            hashStr += hex;
        }
        return hashStr;
    }

    // calculate the Merkle root of the block
    string calculateMerkleRoot()
    {
        if (votes.empty())
        {
            return "";
        }

        vector<string> merkleTree = votes;
        while (merkleTree.size() > 1) // build a Merkle tree layer by layer until there's only one root hash left
        {
            if (merkleTree.size() % 2 != 0) // if the number of elements currently in the tree is odd, then duplicate the last element
            {
                merkleTree.push_back(merkleTree.back());
            }
            vector<string> newMerkleTree;
            // compute the hashes of each pair of elements in the current layer and append it to the temporary newMerkleTree vector
            for (int i = 0; i < merkleTree.size(); i += 2)
            {
                // concatenate two adjacent nodes
                string combined = merkleTree[i] + merkleTree[i + 1];
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256((unsigned char *)combined.c_str(), combined.length(), hash);
                string hashStr = "";
                for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
                {
                    char hex[3];
                    snprintf(hex, 3, "%02x", hash[j]);
                    hashStr += hex;
                }
                // hash the combined string and append to the newMerkleTree vector
                newMerkleTree.push_back(hashStr);
            }
            // replace the original Merkle tree layer with the new layer
            merkleTree = newMerkleTree;
        }
        // return the first (and only) element once the Merkle tree's size reduces to one; this is the final root hash
        // in case the original Merkle tree had size one, the element is the hash itself
        return merkleTree[0];
    }
};

// class to represent the blockchain
class Blockchain
{
private:
    vector<Block> chain;

public:
    Blockchain()
    {
        // initialize the blockchain with a genesis block
        vector<string> votes;
        string previousHash = "0";
        Block genesisBlock(0, votes, previousHash);
        chain.push_back(genesisBlock);
    }

    // add a new block to the blockchain
    void addBlock(vector<string> votes)
    {
        int index = chain.size();
        string previousHash = chain[index - 1].hash;

        Block newBlock(index, votes, previousHash);
        chain.push_back(newBlock);
    }

    // get the blockchain
    vector<Block> getChain()
    {
        // reverse the chain to get it in the correct order
        vector<Block> chainReversed(chain.rbegin(), chain.rend());
        return chainReversed;
    }

    // get the blockchain length
    int getBlockchainLength() const
    {
        return chain.size();
    }
};

// class to represent a voter
class Voter
{
public:
    // stores the voter ID and candidate voted for (A, B, C, D)
    string uniqueId;
    string candidate;
    // Default constructor
    Voter() : uniqueId(""), candidate("") {}
    Voter(string uniqueId) : uniqueId(uniqueId), candidate("") {}

    // check if the voter has already cast a vote
    bool hasVoted() const
    {
        return !candidate.empty();
    }
};

// VotingSystem class to manage the voting system
class VotingSystem
{
private:
    // unique voter IDs of registered voters
    map<string, Voter> registeredVoters;
    // contesting candidates
    vector<string> candidates = {"A", "B", "C", "D"};
    // encrypted voter ID and the corresponding candidate
    map<string, string> collectedVotes;

    // uses SHA-256 from EVP to encrypt the voter ID
    string encryptVoterId(const string &uniqueId)
    {
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        OpenSSL_add_all_digests();
        md = EVP_get_digestbyname("sha256");

        if (md == NULL)
        {
            cerr << "SHA-256 not supported!" << endl;
            EVP_cleanup();
            return "";
        }

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, uniqueId.c_str(), uniqueId.size());
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_free(mdctx);

        char hashStr[2 * SHA256_DIGEST_LENGTH + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(&hashStr[i * 2], "%02x", md_value[i]);
        }
        return string(hashStr);
    }

public:
    void registerVoter(string uniqueId)
    {
        // checks if the voter is already registered
        if (registeredVoters.find(encryptVoterId(uniqueId)) != registeredVoters.end())
        {
            cout << "Voter with ID " << uniqueId << " is already registered." << endl;
        }
        else
        {
            // registers the voter
            Voter voter(encryptVoterId(uniqueId));
            registeredVoters[encryptVoterId(uniqueId)] = voter;
            cout << "Voter with ID " << uniqueId << " has been registered." << endl;
        }
    }

    // casts a vote
    void castVote(string uniqueId, string candidate)
    {
        string encryptedId = encryptVoterId(uniqueId);
        // checks if the voter is registered
        if (registeredVoters.find(encryptedId) == registeredVoters.end())
        {
            cout << "Voter with ID " << uniqueId << " is not registered." << endl;
            return;
        }

        // checks if the voter has already voted
        if (registeredVoters[encryptedId].hasVoted())
        {
            cout << "Voter with ID " << uniqueId << " has already cast a vote." << endl;
            return;
        }

        // checks if the candidate is valid
        if (find(candidates.begin(), candidates.end(), candidate) == candidates.end())
        {
            cout << "Invalid candidate choice." << endl;
            return;
        }

        // records the vote
        registeredVoters[encryptedId].candidate = candidate;
        cout << "Voter with ID " << uniqueId << " has successfully cast a vote for candidate " << candidate << "." << endl;

        collectedVotes[encryptedId] = candidate;
    }
    
    // get the registered voters
    map<string, Voter> getRegisteredVoters() const
    {
        return registeredVoters;
    }

    // get the list of candidates (public)
    vector<string> getCandidates() const
    {
        return candidates;
    }
    // get the final list of votes cast
    map<string, string> getCollectedVotes() const
    {
        return collectedVotes;
    }
};

// gets rid of whitespace
string trim(const string &str)
{
    // Find the first non-whitespace character
    size_t first = str.find_first_not_of(" \t\n\r");

    // If the string is all whitespace, return an empty string
    if (first == string::npos)
    {
        return "";
    }

    // Find the last non-whitespace character
    size_t last = str.find_last_not_of(" \t\n\r");

    // Return the substring without leading and trailing whitespace
    return str.substr(first, (last - first + 1));
}

int main()
{
    Blockchain blockchain;
    VotingSystem votingSystem;
    // define a block size (4 votes per block)
    const int blockSize = 4;
    while (true)
    {
        // main menu
        cout << "\nBlockchain Voting System:" << endl;
        cout << "1. View Candidates" << endl;
        cout << "2. Register Voter" << endl;
        cout << "3. Cast Vote" << endl;
        cout << "4. Admin Controls" << endl;
        cout << "5. Exit" << endl;
        int choice;
        cout << "Enter your choice: ";
        cin >> choice;

        if (choice == 1) // display the list of candidates
        {
            vector<string> candidates = votingSystem.getCandidates();
            cout << "List of Candidates: " << endl;
            for (const string &candidate : candidates)
            {
                cout << candidate << endl;
            }
        }
        else if (choice == 2) // register the voters
        {
            string uniqueId;
            cout << "Enter the unique ID of the voter: ";
            cin >> uniqueId;

            // Encrypt or hash the uniqueId before registering the voter
            votingSystem.registerVoter(uniqueId);
        }
        else if (choice == 3) // cast a vote
        {
            string uniqueId, candidate;
            cout << "Enter your voter ID: ";
            cin >> uniqueId;
            cout << "Enter your vote (Candidate A, Candidate B, Candidate C, Candidate D): ";
            cin.ignore();
            getline(cin, candidate);
            votingSystem.castVote(uniqueId, candidate);
        }
        else if (choice == 4) // access administrator controls for the entire system
        {
            string input, password;
            password = "abc123";
            cout << "Enter the password for admin access: ";
            cin >> input;
            cin.ignore();
            int bc_length, bc_gen_flag = 0;
            if (password == input)
            {
                // only allow access if the correct password is entered
                cout << "Access granted." << endl;
                while (true)
                {
                    // admin menu
                    cout << "\nAdmin Controls:" << endl;
                    cout << "1) End Election (Generate Blockchain)" << endl;
                    cout << "2) Tally Votes" << endl;
                    cout << "3) View a Single Block" << endl;
                    cout << "4) View Full Blockchain" << endl;
                    cout << "5) Demonstrate Blockchain Immutability" << endl;
                    cout << "6) Exit to Main Menu" << endl;
                    int adChoice;
                    cout << "Enter your choice: ";
                    cin >> adChoice;

                    if (adChoice == 1) // end the election and generate a blockchain from the final list of votes
                    {
                        if (bc_gen_flag == 0)
                        {
                            map<string, string> collectedVotes = votingSystem.getCollectedVotes();

                            vector<string> votes;
                            int temp_count = 0;
                            int long_count = 0;
                            for (const auto &vote : collectedVotes)
                            {
                                votes.push_back(vote.first + ": " + vote.second);
                                temp_count++;
                                long_count++;
                                if (temp_count == blockSize)
                                {
                                    blockchain.addBlock(votes);
                                    votes.clear();
                                    temp_count = 0;
                                }
                                else
                                {
                                    if (long_count == collectedVotes.size())
                                    {
                                        blockchain.addBlock(votes);
                                        votes.clear();
                                        temp_count = 0;
                                    }
                                }
                            }
                            collectedVotes.clear();
                            bc_length = blockchain.getBlockchainLength();
                            cout << "Blockchain generated, " << bc_length << " blocks long." << endl;
                            bc_gen_flag = 1;
                        }
                        else
                        {
                            cout << "Blockchain already generated." << endl;
                        }
                    }
                    else if (adChoice == 2) // tally the votes and declare the election winner
                    {
                        map<string, string> collectedVotes = votingSystem.getCollectedVotes();
                        map<string, int> totalVotes;
                        for (const string &candidate : votingSystem.getCandidates())
                        {
                            totalVotes[candidate] = 0;
                        }
                        for (const auto &vote : collectedVotes)
                        {
                            totalVotes[vote.second]++;
                        }
                        for (const string &candidate : votingSystem.getCandidates())
                        {
                            cout << "Candidate " << candidate << ": " << totalVotes[candidate] << endl;
                        }
                        int max_value = -1;
                        string max_key;
                        for (const auto &pair : totalVotes)
                        {
                            if (pair.second > max_value)
                            {
                                max_value = pair.second;
                                max_key = pair.first;
                            }
                        }
                        cout << "The election winner is Candidate " << max_key << "." << endl;
                    }
                    else if (adChoice == 3) // print a single block's contents from the blockchain
                    {
                        int blockNum;
                        cout << "Enter the block number to access (range 0-" << bc_length - 1 << "): ";
                        cin >> blockNum;
                        cin.ignore();
                        int j = 0;
                        for (const Block &block : blockchain.getChain())
                        {
                            if (blockNum >= bc_length)
                            {
                                break;
                            }
                            else if (j == bc_length - blockNum - 1)
                            {
                                cout << "Block Index: " << block.index << endl;
                                cout << "Block Hash: " << block.hash << endl;
                                if (block.merkleRoot == "")
                                {
                                    cout << "Merkle Root: N/A" << endl;
                                }
                                cout << "Previous Hash: " << block.previousHash << endl;
                                cout << "Timestamp: " << asctime(localtime(&block.timestamp));
                                cout << "Votes:" << endl;
                                if (block.votes.empty())
                                {
                                    cout << "N/A";
                                }
                                else
                                {
                                    int i = 0;
                                    for (const string &vote : block.votes)
                                    {
                                        cout << i << ") " << vote << endl;
                                        i++;
                                    }
                                }
                                cout << "\n\n";
                                break;
                            }
                            else
                            {
                                j++;
                            }
                        }
                    }
                    else if (adChoice == 4) // print the contents of all the blocks in the blockchain
                    {
                        for (const Block &block : blockchain.getChain())
                        {
                            cout << "Block Index: " << block.index << endl;
                            cout << "Block Hash: " << block.hash << endl;
                            if (block.merkleRoot == "")
                            {
                                cout << "Merkle Root: "
                                     << "N/A" << endl;
                            }
                            cout << "Previous Hash: " << block.previousHash << endl;
                            cout << "Timestamp: " << asctime(localtime(&block.timestamp));
                            cout << "Votes:" << endl;
                            if (block.votes.empty())
                            {
                                cout << "N/A";
                            }
                            else
                            {
                                int i = 0;
                                for (const string &vote : block.votes)
                                {
                                    cout << i << ") " << vote << endl;
                                    i++;
                                }
                            }
                            cout << "\n\n";
                        }
                    }
                    else if (adChoice == 5) // try and tamper with a particular vote (used to demonstrate immutability of blockchain)
                    {
                        int blockNum;
                        cout << "Enter the block number to tamper (range 0-" << bc_length - 1 << "): ";
                        cin >> blockNum;
                        cin.ignore();
                        int j = 0;
                        vector<string> modifiedVotes, originalVotes;
                        string previousHash;
                        for (const Block &block : blockchain.getChain())
                        {
                            if (blockNum >= bc_length)
                            {
                                break;
                            }
                            else if (j == bc_length - blockNum - 1)
                            {
                                cout << "Block Index: " << block.index << endl;
                                cout << "Block Hash: " << block.hash << endl;
                                if (block.merkleRoot == "")
                                {
                                    cout << "Merkle Root: N/A" << endl;
                                }
                                cout << "Previous Hash: " << block.previousHash << endl;
                                previousHash = block.previousHash;
                                cout << "Timestamp: " << asctime(localtime(&block.timestamp));
                                cout << "Votes:" << endl;
                                if (block.votes.empty())
                                {
                                    cout << "N/A";
                                }
                                else
                                {
                                    modifiedVotes = block.votes;
                                    originalVotes = block.votes;
                                    int i = 0;
                                    for (const string &vote : block.votes)
                                    {
                                        cout << i << ") " << vote << endl;
                                        i++;
                                    }
                                }
                                cout << "\n\n";
                                break;
                            }
                            else
                            {
                                j++;
                            }
                        }
                        int voteToModify;
                        cout << "Enter the candidate whose vote is to be tampered: ";
                        cin >> voteToModify;
                        string temp;
                        cout << "Enter the new vote: ";
                        cin >> temp;
                        string newCandidate = trim(temp);
                        string x = modifiedVotes[voteToModify];
                        x = x.substr(0, x.size() - 1) + newCandidate;
                        modifiedVotes[voteToModify] = x;
                        Block originalBlock(blockNum, originalVotes, previousHash);
                        Block modifiedBlock(blockNum, modifiedVotes, previousHash);
                        // Calculate the Merkle root for the original votes
                        string originalMerkleRoot = originalBlock.calculateMerkleRoot();

                        // Calculate the Merkle root for the modified votes
                        string modifiedMerkleRoot = modifiedBlock.calculateMerkleRoot();

                        // Display the results
                        cout << "Original Merkle Root (Block " << blockNum << "): " << originalMerkleRoot << endl;
                        cout << "Modified Merkle Root (Block " << blockNum << "): " << modifiedMerkleRoot << endl;

                        if (originalMerkleRoot != modifiedMerkleRoot)
                        {
                            cout << "Merkle Roots do not match. The blockchain is immutable." << endl;
                        }
                        else
                        {
                            cout << "Merkle Roots match. The blockchain is secure." << endl;
                        }
                    }
                    else if (adChoice == 6) // exit admin menu
                    {
                        cout << "Exiting admin contol." << endl;
                        break;
                    }
                }
            }
            else
            {
                cout << "Access denied. Wrong password." << endl;
            }
        }
        else if (choice == 5) // exit main program
        {
            cout << "Exiting program." << endl;
            break;
        }
        else
        {
            cout << "Invalid choice." << endl;
        }
    }

    return 0;
}
