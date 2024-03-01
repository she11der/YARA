private rule ESET_Potaodll_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "a53ff170-ed3a-5ee9-a262-bb2f77aba092"
		date = "2015-07-30"
		modified = "2015-07-30"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/potao/PotaoNew.yara#L46-L70"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "1d1154eb10cc70b3252e3ca4a85789e8605f2f3b7044f03ec960fd56ab81886a"
		score = 75
		quality = 28
		tags = ""

	strings:
		$mz = { 4d 5a }
		$dllstr1 = "?AVCncBuffer@@"
		$dllstr2 = "?AVCncRequest@@"
		$dllstr3 = "Petrozavodskaya, 11, 9"
		$dllstr4 = "_Scan@0"
		$dllstr5 = "\x00/sync/document/"
		$dllstr6 = "\\temp.temp"
		$dllname1 = "node69MainModule.dll"
		$dllname2 = "node69-main.dll"
		$dllname3 = "node69MainModuleD.dll"
		$dllname4 = "task-diskscanner.dll"
		$dllname5 = "\x00Screen.dll"
		$dllname6 = "Poker2.dll"
		$dllname7 = "PasswordStealer.dll"
		$dllname8 = "KeyLog2Runner.dll"
		$dllname9 = "GetAllSystemInfo.dll"
		$dllname10 = "FilePathStealer.dll"

	condition:
		($mz at 0) and ( any of ($dllstr*) and any of ($dllname*))
}
