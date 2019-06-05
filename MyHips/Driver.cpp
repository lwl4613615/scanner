#include "Driver.h"
#include <Windows.h>
#pragma comment(lib,"Advapi32.lib")

Driver::Driver()
{
}


Driver::~Driver()
{
}

bool Driver::InstallDriver(const char* lpszDriverName, const char* lpszDriverPath, const char* lpszAltitude)
{
	char    szTempStr[MAX_PATH];
	HKEY    hKey;
	DWORD    dwData;
	char    szDriverImagePath[MAX_PATH];

    if (nullptr == lpszDriverName || nullptr == lpszDriverPath)
	{
		return FALSE;
	}
	strcpy_s(m_szDriverName, MAX_PATH, lpszDriverName);
	//�õ�����������·��
    GetFullPathNameA(lpszDriverPath, MAX_PATH, szDriverImagePath, nullptr);

    SC_HANDLE hServiceMgr = nullptr;// SCM�������ľ��
    SC_HANDLE hService = nullptr;// NT��������ķ�����

	//�򿪷�����ƹ�����
    hServiceMgr = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == nullptr)
	{
		// OpenSCManagerʧ��
		CloseServiceHandle(hServiceMgr);
		return FALSE;
	}

	// OpenSCManager�ɹ�  

	//������������Ӧ�ķ���
	hService = CreateServiceA(hServiceMgr,
		lpszDriverName,             // �����������ע����е�����
		lpszDriverName,             // ע������������DisplayName ֵ
		SERVICE_ALL_ACCESS,         // ������������ķ���Ȩ��
		SERVICE_FILE_SYSTEM_DRIVER, // ��ʾ���صķ������ļ�ϵͳ��������
		SERVICE_DEMAND_START,       // ע������������Start ֵ
		SERVICE_ERROR_IGNORE,       // ע������������ErrorControl ֵ
		szDriverImagePath,          // ע������������ImagePath ֵ
		"FSFilter Activity Monitor",// ע������������Group ֵ
        nullptr,
		"FltMgr",                   // ע������������DependOnService ֵ
        nullptr,
        nullptr);

    if (hService == nullptr)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			//���񴴽�ʧ�ܣ������ڷ����Ѿ�������
			CloseServiceHandle(hService);       // ������
			CloseServiceHandle(hServiceMgr);    // SCM���
			return TRUE;
		}
		else
		{
			CloseServiceHandle(hService);       // ������
			CloseServiceHandle(hServiceMgr);    // SCM���
			return FALSE;
		}
	}
	CloseServiceHandle(hService);       // ������
	CloseServiceHandle(hServiceMgr);    // SCM���

	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances�ӽ��µļ�ֵ�� 
	//-------------------------------------------------------------------------------------------------------
	strcpy_s(szTempStr, MAX_PATH,"SYSTEM\\CurrentControlSet\\Services\\");
	strcat_s(szTempStr, MAX_PATH,lpszDriverName);
	strcat_s(szTempStr, MAX_PATH,"\\Instances");
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, szTempStr, 0, const_cast<char *>(""), REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// ע������������DefaultInstance ֵ 
	strcpy_s(szTempStr, MAX_PATH, lpszDriverName);
	strcat_s(szTempStr, MAX_PATH," Instance");
	if (RegSetValueExA(hKey, "DefaultInstance", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//ˢ��ע���
	RegCloseKey(hKey);


	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances\\DriverName Instance�ӽ��µļ�ֵ�� 
	//-------------------------------------------------------------------------------------------------------
	strcpy_s(szTempStr, MAX_PATH,"SYSTEM\\CurrentControlSet\\Services\\");
	strcat_s(szTempStr, MAX_PATH,lpszDriverName);
	strcat_s(szTempStr, MAX_PATH,"\\Instances\\");
	strcat_s(szTempStr, MAX_PATH,lpszDriverName);
	strcat_s(szTempStr, MAX_PATH," Instance");
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, szTempStr, 0,const_cast<char *>(""), REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// ע������������Altitude ֵ
	strcpy_s(szTempStr, MAX_PATH, lpszAltitude);
    if (RegSetValueExA(hKey, "Altitude", 0, REG_SZ, (CONST BYTE*)szTempStr, static_cast<DWORD>(strlen(szTempStr)) != ERROR_SUCCESS))
	{
		return FALSE;
	}
	// ע������������Flags ֵ
	dwData = 0x0;
	if (RegSetValueExA(hKey, "Flags", 0, REG_DWORD, (CONST BYTE*)&dwData, sizeof(DWORD)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//ˢ��ע���
	RegCloseKey(hKey);

	return TRUE;
}

bool Driver::StartDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;

    if (nullptr == lpszDriverName)
	{
		return FALSE;
	}

    schManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (nullptr == schManager)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	schService = OpenServiceA(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
    if (nullptr == schService)
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

    if (!StartService(schService, 0, nullptr))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
		{
			// �����Ѿ�����
			return TRUE;
		}
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}

bool Driver::StopDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;


    schManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (nullptr == schManager)
	{
		return FALSE;
    }
	schService = OpenServiceA(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
    if (nullptr == schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	if (!ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus) && (svcStatus.dwCurrentState != SERVICE_STOPPED))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}

bool Driver::DeleteDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;

    schManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (nullptr == schManager)
	{
		return FALSE;
	}
	schService = OpenServiceA(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
    if (nullptr == schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus);
	if (!DeleteService(schService))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}


char* Driver::GetDriverName()
{
	return m_szDriverName;
}
