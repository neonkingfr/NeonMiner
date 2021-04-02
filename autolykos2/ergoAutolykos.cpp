#include "ergoAutolykos.h"


std::atomic<int> end_jobs(0);

ergoAutolykos::ergoAutolykos()
{
}


ergoAutolykos::~ergoAutolykos()
{
}
#include <condition_variable>

void ergoAutolykos::SenderThread(info_t * info, BlockQueue<MinerShare>* shQueue)
{
	el::Helpers::setThreadName("sender thread");

	while (true)
	{
		MinerShare share = shQueue->get();
		char logstr[2048];

			LOG(INFO) << "Some GPU found and trying to POST a share: " ;
			PostPuzzleSolution(info->to, (uint8_t*)&share.nonce);

	}


}
////////////////////////////////////////////////////////////////////////////////
//  Miner thread cycle
////////////////////////////////////////////////////////////////////////////////
void ergoAutolykos::MinerThread(CLWarpper *clw, const  int deviceId, const int totalGPUCards, info_t * info, std::vector<double>* hashrates, std::vector<int>* tstamps, BlockQueue<MinerShare>* shQueue)
{
	char threadName[20];
	sprintf(threadName, "GPU %i miner", deviceId);
	el::Helpers::setThreadName(threadName);
	LOG(INFO) << "Gpu " << deviceId << " Started";

	state_t state = STATE_KEYGEN;

	//========================================================================//
	//  Host memory allocation
	//========================================================================//
	// CURL http request
	json_t request(0, REQ_LEN);

	// hash context
	// (212 + 4) bytes
	ctx_t ctx_h;

	// autolykos variables
	uint8_t bound_h[NUM_SIZE_8];
	uint8_t mes_h[NUM_SIZE_8];
	uint8_t res_h[NUM_SIZE_8];
	uint8_t nonce[NONCE_SIZE_8];

	char to[MAX_URL_SIZE];
	int keepPrehash = 0;

	char tmpBuff[PK_SIZE_8 + PK_SIZE_8 + NUM_SIZE_8];
	// thread info variables
	uint_t blockId = 0;
	milliseconds start;

	//========================================================================//
	//  Copy from global to thread local data
	//========================================================================//
	info->info_mutex.lock();


	memcpy(mes_h, info->mes, NUM_SIZE_8);
	memcpy(bound_h, info->bound, NUM_SIZE_8);
	memcpy(to, info->to, MAX_URL_SIZE * sizeof(char));
	// blockId = info->blockId.load();
	keepPrehash = info->keepPrehash;

	info->info_mutex.unlock();

	//========================================================================//
	//  Check GPU memory
	//========================================================================//
	size_t freeMem = 0;
	size_t totalMem = 0;

	cl_ulong max_mem_alloc_size = clw->getDeviceInfoInt64(CL_DEVICE_MAX_MEM_ALLOC_SIZE);
	cl_ulong mem_size = clw->getDeviceInfoInt64(CL_DEVICE_GLOBAL_MEM_SIZE);


	LOG(INFO) << "GPU " << clw->m_gpuIndex << " mem_size: " << clw->getGlobalSizeMB() << "  (MB) , max_mem_alloc_size: " << clw->getMaxAllocSizeMB() << " (MB) ";
	size_t uctx_t_count = max_mem_alloc_size / sizeof(uctx_t);

	size_t memCount = (N_LEN / uctx_t_count) + 1;
	size_t n_len = N_LEN;

	if (max_mem_alloc_size < MIN_FREE_MEMORY)
	{
		LOG(ERROR) << "GPU " << clw->m_gpuIndex << " Not enough GPU memory for mining,"
				<< " minimum 2.8 GiB needed";

		return;
	}

	if (keepPrehash && (memCount > 2 || memCount < 0))
	{
		LOG(ERROR) << "GPU " << clw->m_gpuIndex << "C: Error in Memory Alloc for KeepPrehash";
		keepPrehash = false;
	}

	//========================================================================//
	//  Device memory allocation
	//========================================================================//
	LOG(INFO) << "GPU " << deviceId << " allocating memory";
	size_t allocatedMem = 0;

	//-------------------------------------------------------------
	// boundary for puzzle
	// (2 * PK_SIZE_8 + 2 + 4 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MiB
	cl_mem bound_d = clw->Createbuffer((NUM_SIZE_8 + DATA_SIZE_8) * sizeof(char), CL_MEM_READ_WRITE);
	if (bound_d == NULL)
	{
		LOG(INFO) << "GPU " << deviceId << "error in  allocating hashbound_des_d";
		return;
	}
	cl_uint* hbound_d = (cl_uint*)malloc((NUM_SIZE_8 + DATA_SIZE_8) * sizeof(char));
	allocatedMem += (NUM_SIZE_8 + DATA_SIZE_8) * sizeof(char);
	//-------------------------------------------------------------
	// data: pk || mes || w || padding || x || sk || ctx
	//cl_uint * data_d = bound_d + NUM_SIZE_32;
	cl_mem data_d = clw->Createbuffer((2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) * sizeof(char), CL_MEM_READ_WRITE);
	if (data_d == NULL)
	{
		LOG(INFO) << "GPU " << deviceId << "error in  allocating data_d";
		return;
	}
	cl_uint* hdata_d = (cl_uint*)malloc((2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) * sizeof(char));
	allocatedMem += (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) * sizeof(char);

	// precalculated hashes
	// N_LEN * NUM_SIZE_8 bytes // 2 GiB
	cl_mem hashes_d = clw->Createbuffer((cl_uint)N_LEN * NUM_SIZE_8 * sizeof(char), CL_MEM_READ_WRITE);
	if (hashes_d == NULL)
	{
		LOG(INFO) << "GPU " << deviceId << "error in  allocating hashes_d";
		return;
	}
	allocatedMem += (cl_uint)N_LEN * NUM_SIZE_8 * sizeof(char);
	//cl_uint* hhashes_d = (cl_uint*)malloc((cl_uint)N_LEN * NUM_SIZE_8 * sizeof(char));


	/////////--------------------------------------------------------------------------------------
	// WORKSPACE_SIZE_8 bytes // depends on macros, now ~512 MiB
	// potential solutions of puzzle

	// indices of unfinalized hashes
	cl_mem indices_d = clw->Createbuffer(MAX_POOL_RES * sizeof(cl_uint), CL_MEM_READ_WRITE);
	if (indices_d == NULL)
	{
		LOG(INFO) << "GPU " << deviceId << "error in  allocating indices_d";
		return;
	}
	cl_uint* hindices_d = (cl_uint*)malloc(MAX_POOL_RES * sizeof(cl_uint));
	allocatedMem += sizeof(cl_uint);

	memset(hindices_d, 0, MAX_POOL_RES * sizeof(cl_uint));
	clw->CopyBuffer(indices_d, hindices_d, MAX_POOL_RES * sizeof(cl_uint), false);

	cl_mem count_d = clw->Createbuffer(sizeof(cl_uint), CL_MEM_READ_WRITE);
	if (count_d == NULL)
	{
		LOG(INFO) << "GPU " << deviceId << "error in  allocating count_d";
		return ;
	}

	cl_uint* hcount_d = (cl_uint*)malloc(sizeof(cl_uint));
	allocatedMem += sizeof(cl_uint);

	memset(hcount_d, 0, sizeof(cl_uint));
	clw->CopyBuffer(count_d, hcount_d, sizeof(cl_uint), false);

	/////////--------------------------------------------------------------------------------------


	// unfinalized hash contexts
	// if keepPrehash == true // N_LEN * 80 bytes // 5 GiB
	cl_mem uctxs_d[100];
	cl_ulong memSize[100];
	uctxs_d[0] = uctxs_d[1] = NULL;
	keepPrehash = 0; //temporary
	if (keepPrehash)
	{
		size_t preS = (cl_uint)N_LEN * sizeof(uctx_t);
		if (memCount > 2 || memCount < 0)
		{
			LOG(INFO) << "C: Error in Memory Alloc for KeepPrehash";
			keepPrehash = false;

		}
		else if ((allocatedMem + preS) < mem_size)
		{

			size_t last = N_LEN % uctx_t_count;
			size_t sz = 0;
			for (size_t i = 0; i < memCount; i++)
			{
				if (i == memCount - 1)
				{
					uctxs_d[i] = clw->Createbuffer(last * sizeof(uctx_t), CL_MEM_READ_WRITE);
					//huctxs_d[i] = (uctx_t*)malloc(last);
					memSize[i] = i * uctx_t_count + last;
				}
				else
				{
					uctxs_d[i] = clw->Createbuffer(uctx_t_count * sizeof(uctx_t), CL_MEM_READ_WRITE);
					//huctxs_d[i] = (uctx_t*)malloc(uctx_t_count * sizeof(uctx_t));
					memSize[i] = i * uctx_t_count + uctx_t_count;
				}
				if (uctxs_d[i] == NULL)
				{
					LOG(INFO) << "A: Error in Memory Alloc for KeepPrehash";
					keepPrehash = false;
				}

			}
		}
		else
		{
			LOG(INFO) << "B: Error in Memory Alloc for KeepPrehash";
			keepPrehash = false;

		}

	}


	//========================================================================//
	//  Autolykos puzzle cycle
	//========================================================================//
	cl_uint countOfP = 0;
	cl_ulong base = 0;
	cl_ulong EndNonce = 0;
	cl_uint height = 0;
	PreHashClass *ph = new PreHashClass(clw);
	MiningClass *min = new MiningClass(clw);

	// set unfinalized hash contexts if necessary
	keepPrehash = false;
	if (keepPrehash)
	{
		LOG(INFO) << "Preparing unfinalized hashes on GPU " << deviceId;
		ph->hUncompleteInitPrehash(data_d, uctxs_d, memSize, memCount);
	}

	int cntCycles = 0;
	int NCycles = 50;
	start = duration_cast<milliseconds>(system_clock::now().time_since_epoch());



	// wait for the very first block to come before starting
	while (info->blockId.load() == 0) {}
	do
	{
		++cntCycles;

		if (!(cntCycles % NCycles))
		{
			milliseconds timediff
			= duration_cast<milliseconds>(
					system_clock::now().time_since_epoch()
			) - start;

			// change avg hashrate in global memory
			(*hashrates)[deviceId] = (double)NONCES_PER_ITER * (double)NCycles
					/ ((double)1000 * timediff.count());


			start = duration_cast<milliseconds>(
					system_clock::now().time_since_epoch()
			);

			(*tstamps)[deviceId] = start.count();
		}

		// if solution was found by this thread wait for new block to come
		if (state == STATE_KEYGEN)
		{
			while (info->blockId.load() == blockId) 
			{
				//LOG(INFO) << "GPU " << deviceId << " solution was found by this thread wait for new block to come ";
			}

			state = STATE_CONTINUE;
		}

		uint_t controlId = info->blockId.load();

		if (blockId != controlId)
		{
			// if info->blockId changed
			// read new message and bound to thread-local mem
			info->info_mutex.lock();

			memcpy(&height, info->Hblock, HEIGHT_SIZE);

			memcpy(mes_h, info->mes, NUM_SIZE_8);

			memcpy(bound_h, info->bound, NUM_SIZE_8);


			memcpy(&EndNonce, info->extraNonceEnd, NONCE_SIZE_8);

			//divide nonces between gpus
			memcpy(&EndNonce, info->extraNonceEnd, NONCE_SIZE_8);
			memcpy(&base, info->extraNonceStart, NONCE_SIZE_8);
			cl_ulong nonceChunk = 1 + (EndNonce - base) / totalGPUCards;
			base = *((cl_ulong *)info->extraNonceStart) + deviceId * nonceChunk;
			EndNonce = base + nonceChunk;


			info->info_mutex.unlock();

			LOG(INFO) << "GPU " << deviceId << " read new block data";
			blockId = controlId;


			VLOG(1) << "Generated new keypair,"
					<< " copying new data in device memory now";

			// copy boundary
			memcpy(hbound_d, (void*)bound_h, NUM_SIZE_8);


			// copy message
			memcpy((uint8_t*)hdata_d + PK_SIZE_8, mes_h, NUM_SIZE_8);


			cl_int ret = clw->CopyBuffer(bound_d, hbound_d, (NUM_SIZE_8 + DATA_SIZE_8) * sizeof(char), false);

			ret = clw->CopyBuffer(data_d, hdata_d, (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) * sizeof(char), false);

			//LOG(INFO) <<  "Starting prehashing with new block data";
			ph->Prehash(height, hashes_d);


			//LOG(INFO) << "Starting InitMining";
			min->InitMining(&ctx_h, (cl_uint*)mes_h, NUM_SIZE_8);
			//// copy context
			ret = clw->CopyBuffer(data_d, hdata_d, (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) * sizeof(char), true);
			memcpy(hdata_d + COUPLED_PK_SIZE_32 + 3 * NUM_SIZE_32, &ctx_h, sizeof(ctx_t));
			ret = clw->CopyBuffer(data_d, hdata_d, (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) * sizeof(char), false);

			state = STATE_CONTINUE;

		}


		VLOG(1) << "Starting main BlockMining procedure";

		memset(hcount_d, 0, sizeof(cl_uint));
		clw->CopyBuffer(count_d, hcount_d, sizeof(cl_uint), false);
		memset(hindices_d, 0, MAX_POOL_RES*sizeof(cl_uint));
		clw->CopyBuffer(indices_d, hindices_d, MAX_POOL_RES*sizeof(cl_uint), false);


		//// calculate solution candidates
		// copy message
		memcpy((uint8_t*)hdata_d, mes_h, NUM_SIZE_8);
		memcpy((uint8_t*)hdata_d+ NUM_SIZE_8, &ctx_h, sizeof(ctx_t));

		cl_int ret = clw->CopyBuffer(data_d, hdata_d, (NUM_SIZE_8+ sizeof(ctx_t)) * sizeof(char), false);
		min->hBlockMining(bound_d, data_d /*mes*/, base, EndNonce, height, hashes_d,indices_d,count_d);
		VLOG(1) << "Trying to find solution";

		// restart iteration if new block was found
		if (blockId != info->blockId.load())
		{
			LOG(INFO) << "GPU " << deviceId << " blockId != info->blockId.load " ;
			continue;
		}


		// try to find solution
		ret = clw->CopyBuffer(indices_d, hindices_d, MAX_POOL_RES* sizeof(cl_uint), true);

		// solution found
		if (hindices_d[0])
		{
			LOG(INFO) << "share found";

			
			int i = 0;
			while ((hindices_d[i]) && (i < MAX_POOL_RES))
			{

				*((uint64_t *)nonce) = base + hindices_d[i] - 1;
				uint64_t endNonceT;
				memcpy(&endNonceT , info->extraNonceEnd , sizeof(uint64_t));
				if ( (*((uint64_t *)nonce)) <= endNonceT )
				{
					//char tmpTest[16];
					//LittleEndianToHexStr(nonce, NONCE_SIZE_8, tmpTest);
					//LOG(INFO) << "GPU  sol: " << i << " index: " << hindices_d[i] << " nonceDecimal: " << nonce <<  " nonceHex: " << tmpTest;

					MinerShare share(*((uint64_t *)nonce));
					shQueue->put(share);


					if (!info->stratumMode)
					{
						state = STATE_KEYGEN;
						//end_jobs.fetch_add(1, std::memory_order_relaxed);
						break;
					}
				}
				else
				{
					//LOG(INFO) << "nonce greater than end nonce, nonce: " << *((uint64_t *)nonce) << " endNonce:  " << endNonceT;
				}
				i++;
			}

		}
		base += NONCES_PER_ITER;

		if (base > EndNonce) 	//end work
		{
			state = STATE_KEYGEN;
			end_jobs.fetch_add(1, std::memory_order_relaxed);
		}

	} while (1);

}

bool ispartof(char* w1, char* w2)
{
	int i = 0;
	int j = 0;


	while (w1[i] != '\0') {
		if (w1[i] == w2[j])
		{
			int init = i;
			while (w1[i] == w2[j] && w2[j] != '\0')
			{
				j++;
				i++;
			}
			if (w2[j] == '\0') {
				return true;
			}
			j = 0;
		}
		i++;
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
int ergoAutolykos::startAutolykos(int argc, char ** argv)
{

	//========================================================================//
	//  Setup log
	//========================================================================//
	el::Loggers::reconfigureAllLoggers(
			el::ConfigurationType::Format, "%datetime %level [%thread] %msg"
	);

	el::Helpers::setThreadName("main thread");

	char logstr[1000];

	//========================================================================//
	//  Check GPU availability
	//========================================================================//
	clw = new CLWarpper*[MAX_MINER];
	for (size_t i = 0; i < MAX_MINER; i++)
	{
		clw[i] = NULL;

	}

	int i, j;
	char* value;
	size_t valueSize;
	cl_uint platformCount;
	cl_platform_id* platforms;
	cl_device_id* device_ids;
	cl_uint maxComputeUnits;
	cl_uint TotaldeviceCount = 0;

	clGetPlatformIDs(0, NULL, &platformCount);
	platforms = (cl_platform_id*)malloc(sizeof(cl_platform_id) * platformCount);
	clGetPlatformIDs(platformCount, platforms, NULL);


	for (int i = 0; i < platformCount; i++)
	{
		cl_uint deviceCount = 0;
		clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, 0, NULL, &deviceCount);
		device_ids = (cl_device_id*)malloc(sizeof(cl_device_id) * deviceCount);
		clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, deviceCount, device_ids, NULL);


		char *pName = NULL;
		size_t size;
		clGetPlatformInfo(platforms[i], CL_PLATFORM_NAME, NULL, pName, &size); // get size of profile char array
		pName = (char*)malloc(size);
		clGetPlatformInfo(platforms[i], CL_PLATFORM_NAME, size, pName, NULL); // get profile char array
		//cout << pName << endl;
		char *aMD = (char *)"AMD";
		char *srcName;
		if (!ispartof(pName, aMD))
		{
			continue;

		}
		for (int j = 0; j < deviceCount; j++)
		{
			clw[TotaldeviceCount] = new CLWarpper(platforms[i], device_ids[j]);
			TotaldeviceCount++;
		}

	}

	LOG(INFO) << "Number Of AMD GPUs: " << (int)TotaldeviceCount;
	int status = EXIT_SUCCESS;

	if (TotaldeviceCount <= 0)
		return EXIT_SUCCESS;

	//LOG(INFO) << "Using " << deviceCount << " GPU devices";
	//========================================================================//
	//  Read configuration file
	//========================================================================//
	char confName[14] = "./config.json";
	char * fileName = (argc == 1) ? confName : argv[1];
	char from[MAX_URL_SIZE];
	info_t info;

	info.blockId = 0;
	info.keepPrehash = 0;

	LOG(INFO) << "Using configuration file " << fileName;

	// check access to config file
	if (access(fileName, F_OK) == -1)
	{
		LOG(ERROR) << "Configuration file " << fileName << " is not found";
		return EXIT_FAILURE;
	}
	// check other required files
	if ( access("MiningKernel.cl", F_OK) == -1 || access("PreHashKernel.cl", F_OK) == -1 || access("OCLdecs.h", F_OK) == -1 || access("OCLdefs.h", F_OK) == -1 )
	{
		LOG(ERROR) << "some required files  ( MiningKernel.cl, PreHashKernel.cl, OCLdecs.h, OCLdefs.h ) are not found";
		return EXIT_FAILURE;
	}


	// read configuration from file
	status = ReadConfig(
			fileName, from, info.to, info.endJob
	);

	if (status == EXIT_FAILURE) { return EXIT_FAILURE; }

	LOG(INFO) << "Block getting URL:\n   " << from;
	LOG(INFO) << "Solution posting URL:\n   " << info.to;

	//========================================================================//
	//  Setup CURL
	//========================================================================//
	// CURL http request
	json_t request(0, REQ_LEN);

	// CURL init
	PERSISTENT_CALL_STATUS(curl_global_init(CURL_GLOBAL_ALL), CURLE_OK);

	//========================================================================//
	//  Fork miner threads
	//========================================================================//
	std::vector<std::thread> miners(TotaldeviceCount);
	std::vector<std::thread> poolSenders(TotaldeviceCount);
	std::vector<double> hashrates(TotaldeviceCount);

	std::vector<int> lastTimestamps(TotaldeviceCount);
	std::vector<int> timestamps(TotaldeviceCount);

	BlockQueue<MinerShare> solQueue;
	std::thread solSender(SenderThread, &info, &solQueue);

	for (int i = 0; i < TotaldeviceCount; ++i)
	{
		if (clw[i] != NULL)
		{
			if (clw[i]->m_gpuIndex != -1)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
				hashrates[i] = -1;

				lastTimestamps[i] = 1;
				timestamps[i] = 0;

				miners[i] = std::thread(MinerThread, clw[i], i,TotaldeviceCount, &info, &hashrates, &timestamps,&solQueue);
			}
			else
			{
				LOG(INFO) << "DONT Start Gpu " << i;
			}
		}
		else
		{
			LOG(INFO) << "DONT Create Gpu " << i;
		}
	}

	// get first block
	status = EXIT_FAILURE;
	while (status != EXIT_SUCCESS)
	{
		status = GetLatestBlock(from, &request, &info, 0);
		std::this_thread::sleep_for(std::chrono::milliseconds(800));
		if (status != EXIT_SUCCESS)
		{
			LOG(INFO) << "Waiting for block data to be published by node...";
		}
	}

	InitializeADL(TotaldeviceCount,clw);
	std::thread httpApi = std::thread(HttpApiThread, &hashrates, clw, TotaldeviceCount);

	//========================================================================//
	//  Main thread get-block cycle
	//========================================================================//
	uint_t curlcnt = 0;
	const uint_t curltimes = 500;

	ch::milliseconds ms = ch::milliseconds::zero();

	// bomb node with HTTP with 10ms intervals, if new block came
	// signal miners with blockId
	while (1)
	{
		milliseconds start = duration_cast<milliseconds>(
				system_clock::now().time_since_epoch()
		);

		// get latest block
		status = GetLatestBlock(from, &request, &info, 0);

		if (status != EXIT_SUCCESS) { LOG(INFO) << "Getting block error"; }

		ms += duration_cast<milliseconds>(
				system_clock::now().time_since_epoch()
		) - start;

		++curlcnt;

		if (!(curlcnt % curltimes))
		{
			LOG(INFO) << "Average curling time "
					<< ms.count() / (double)curltimes << " ms";
			LOG(INFO) << "Current block candidate: " << request.ptr;
			ms = milliseconds::zero();
			std::stringstream hrBuffer;
			hrBuffer << "Average hashrates: ";
			double totalHr = 0;
			for (int i = 0; i < TotaldeviceCount; ++i)
			{

				// check if miner thread is updating hashrate, e.g. alive
				if (!(curlcnt % (5 * curltimes)))
				{
					if (lastTimestamps[i] == timestamps[i])
					{
						hashrates[i] = 0;
					}
					lastTimestamps[i] = timestamps[i];
				}


				hrBuffer << "GPU" << i << " " << hashrates[i] << " MH/s ";
				totalHr += hashrates[i];
			}
			hrBuffer << "Total " << totalHr << " MH/s ";
			LOG(INFO) << hrBuffer.str();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(60));

		int completeMiners = end_jobs.load();
		if (completeMiners >= TotaldeviceCount)
		{
			end_jobs.store(0);
			JobCompleted(info.endJob);
		}
	}

	return EXIT_SUCCESS;
}
