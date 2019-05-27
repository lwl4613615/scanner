#pragma once
#include <tchar.h>
class Driver
{
public:
	Driver();
	~Driver();
public:
	bool InstallDriver(const char* lpszDriverName, const char* lpszDriverPath, const char* lpszAltitude);
	

	bool StartDriver(const char* lpszDriverName);
	

	bool StopDriver(const char* lpszDriverName);
	

	bool DeleteDriver(const char* lpszDriverName);

	char* GetDriverName();
	
private:
	char m_szDriverName[MAX_PATH];
};

