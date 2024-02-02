rule SIGNATURE_BASE_Irontiger_Wmiexec
{
	meta:
		description = "Iron Tiger Tool - wmi.vbs detection"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "a3060f50-3594-5da9-98e2-6fa0087451f5"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_irontiger_trendmicro.yar#L259-L276"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "7988b993345e13b64e5f02ecd2679fc484b063a4cd2f18b52d00d2dfa34d82cb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$str1 = "Temp Result File , Change it to where you like" wide ascii
		$str2 = "wmiexec" wide ascii
		$str3 = "By. Twi1ight" wide ascii
		$str4 = "[both mode] ,delay TIME to read result" wide ascii
		$str5 = "such as nc.exe or Trojan" wide ascii
		$str6 = "+++shell mode+++" wide ascii
		$str7 = "win2008 fso has no privilege to delete file" wide ascii

	condition:
		2 of ($str*)
}