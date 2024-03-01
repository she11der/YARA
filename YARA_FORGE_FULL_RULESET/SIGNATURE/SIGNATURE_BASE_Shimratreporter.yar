rule SIGNATURE_BASE_Shimratreporter
{
	meta:
		description = "Detects ShimRatReporter"
		author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
		id = "01688b3c-2f06-518f-939d-4d65529be5ae"
		date = "2015-11-20"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_mofang.yar#L28-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "931d65628e5f0b7c63fe270b0a6cd3890f41a4ee7e253ce056b37f2d55542258"
		score = 75
		quality = 85
		tags = ""

	strings:
		$IpInfo = "IP-INFO"
		$NetworkInfo = "Network-INFO"
		$OsInfo = "OS-INFO"
		$ProcessInfo = "Process-INFO"
		$BrowserInfo = "Browser-INFO"
		$QueryUserInfo = "QueryUser-INFO"
		$UsersInfo = "Users-INFO"
		$SoftwareInfo = "Software-INFO"
		$AddressFormat = "%02X-%02X-%02X-%02X-%02X-%02X"
		$proxy_str = "(from environment) = %s"
		$netuserfun = "NetUserEnum"
		$networkparams = "GetNetworkParams"

	condition:
		all of them
}
