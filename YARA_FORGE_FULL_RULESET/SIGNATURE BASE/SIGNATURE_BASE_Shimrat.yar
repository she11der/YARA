rule SIGNATURE_BASE_Shimrat
{
	meta:
		description = "Detects ShimRat and the ShimRat loader"
		author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
		id = "21431895-1180-5552-8e82-1589992ffa1d"
		date = "2015-11-20"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_mofang.yar#L1-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0dd19e6a65b06bd5846ec224f01c3feea066540317223d1991154b2305882b20"
		score = 75
		quality = 85
		tags = ""

	strings:
		$dll = ".dll"
		$dat = ".dat"
		$headersig = "QWERTYUIOPLKJHG"
		$datasig = "MNBVCXZLKJHGFDS"
		$datamarker1 = "Data$$00"
		$datamarker2 = "Data$$01%c%sData"
		$cmdlineformat = "ping localhost -n 9 /c %s > nul"
		$demoproject_keyword1 = "Demo"
		$demoproject_keyword2 = "Win32App"
		$comspec = "COMSPEC"
		$shim_func1 = "ShimMain"
		$shim_func2 = "NotifyShims"
		$shim_func3 = "GetHookAPIs"

	condition:
		($dll and $dat and $headersig and $datasig) or ($datamarker1 and $datamarker2) or ($cmdlineformat and $demoproject_keyword1 and $demoproject_keyword2 and $comspec) or ($dll and $dat and $shim_func1 and $shim_func2 and $shim_func3)
}
