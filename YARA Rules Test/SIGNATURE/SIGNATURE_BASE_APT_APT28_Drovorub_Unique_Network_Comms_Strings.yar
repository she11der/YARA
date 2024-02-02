rule SIGNATURE_BASE_APT_APT28_Drovorub_Unique_Network_Comms_Strings
{
	meta:
		description = "Rule to detect Drovorub-server, Drovorub-agent, or Drovorub-client based"
		author = "NSA / FBI"
		id = "c6a930e8-c1c0-5d96-9051-7516df848b45"
		date = "2020-08-13"
		modified = "2023-12-05"
		reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_apt28_drovorub.yar#L44-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8c82766b76c36fe64c6aa99577e1997d7181dbd36a4c27329845ae8a413f5327"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s_01 = "action" wide ascii
		$s_02 = "auth.commit" wide ascii
		$s_03 = "auth.hello" wide ascii
		$s_04 = "auth.login" wide ascii
		$s_05 = "auth.pending" wide ascii
		$s_06 = "client_id" wide ascii
		$s_07 = "client_login" wide ascii
		$s_08 = "client_pass" wide ascii
		$s_09 = "clientid" wide ascii
		$s_10 = "clientkey_base64" wide ascii
		$s_11 = "file_list_request" wide ascii
		$s_12 = "module_list_request" wide ascii
		$s_13 = "monitor" wide ascii
		$s_14 = "net_list_request" wide ascii
		$s_15 = "server finished" wide ascii
		$s_16 = "serverid" wide ascii
		$s_17 = "tunnel" wide ascii

	condition:
		all of them
}