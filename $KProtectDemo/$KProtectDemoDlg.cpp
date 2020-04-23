
// $KProtectDemoDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "$KProtectDemo.h"
#include "$KProtectDemoDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#include "AntiDebug.h"

DWORD WINAPI LoopThread(LPVOID lpParameter)
{
	while (true)
	{
		Sleep(1000);
		GetKernelDebugger(lpParameter);
	}
}


// CKProtectDemoDlg 对话框



CKProtectDemoDlg::CKProtectDemoDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_KPROTECTDEMO_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CKProtectDemoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CKProtectDemoDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CKProtectDemoDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CKProtectDemoDlg 消息处理程序

BOOL CKProtectDemoDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	CreateThread(NULL, 0, LoopThread, GetCurrentThread(), 0, NULL);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CKProtectDemoDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CKProtectDemoDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}




void CKProtectDemoDlg::OnBnClickedButton1()
{
	MessageBox(L"那怎么可能兑现呢 扯鸡巴蛋呢", L"某总：", MB_OK);
}
