rule SIGNATURE_BASE_CN_Actor_Ammyyadmin : FILE
{
	meta:
		description = "Detects Ammyy Admin Downloader"
		author = "Florian Roth (Nextron Systems)"
		id = "08ffb61a-e2de-538e-9d9f-040276324af9"
		date = "2017-06-22"
		modified = "2023-12-05"
		reference = "Internal Research - CN Actor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_cn_group_btc.yar#L47-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b628c7e6debdd2b21a321dc2ec5838fd56107f4cac21bda8b9faa1c1d5b23b71"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"

	strings:
		$x2 = "\\Ammyy\\sources\\main\\Downloader.cpp" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
