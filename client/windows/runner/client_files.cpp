#include "client_files.h"
#include <windows.h>
#include <commdlg.h>
#include <string>

void HandleClientFiles(const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  const bool saving=call.method_name()=="chooseCsvExport";
  if(!saving && call.method_name()!="chooseCsvImport") {result->NotImplemented();return;}
  wchar_t file[32768]={};
  if(saving) wcscpy_s(file,L"ByteLocker-export.csv");
  OPENFILENAMEW dialog={};dialog.lStructSize=sizeof(dialog);dialog.hwndOwner=GetActiveWindow();
  dialog.lpstrFilter=L"CSV (*.csv)\0*.csv\0All files (*.*)\0*.*\0\0";
  dialog.lpstrFile=file;dialog.nMaxFile=32768;dialog.lpstrDefExt=L"csv";
  dialog.Flags=OFN_EXPLORER|OFN_NOCHANGEDIR|OFN_PATHMUSTEXIST|(saving?OFN_OVERWRITEPROMPT:OFN_FILEMUSTEXIST);
  const BOOL selected=saving?GetSaveFileNameW(&dialog):GetOpenFileNameW(&dialog);
  if(!selected){if(CommDlgExtendedError())result->Error("FILE_UNAVAILABLE","File dialog unavailable");else result->Success();return;}
  const int length=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,file,-1,nullptr,0,nullptr,nullptr);
  if(length<=1){result->Error("FILE_UNAVAILABLE","Invalid filename");return;}
  std::string utf8(static_cast<size_t>(length),'\0');
  WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,file,-1,utf8.data(),length,nullptr,nullptr);utf8.pop_back();
  result->Success(flutter::EncodableValue(utf8));
}
