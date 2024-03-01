rule SIGNATURE_BASE_MAL_Fortinet_COATHANGER_Files : COATHANGER FILE
{
	meta:
		description = "Detects COATHANGER files by used filenames"
		author = "NLD MIVD - JSCU"
		id = "0aa2f266-247b-5510-9fd9-4c7940fb80e8"
		date = "2024-02-06"
		modified = "2024-02-16"
		reference = "https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/mal_fortinet_coathanger_feb24.yar#L16-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5406d8a99e16f08f1ffca548ea1dd1e27e7707506e796e0fc263bcdbb681632d"
		score = 75
		quality = 85
		tags = "COATHANGER, FILE"
		malware = "COATHANGER"

	strings:
		$1 = "/data2/"
		$2 = "/httpsd"
		$3 = "/preload.so"
		$4 = "/authd"
		$5 = "/tmp/packfile"
		$6 = "/smartctl"
		$7 = "/etc/ld.so.preload"
		$8 = "/newcli"
		$9 = "/bin/busybox"

	condition:
		( uint32(0)==0x464c457f or uint32(4)==0x464c457f) and filesize <5MB and 4 of them
}
