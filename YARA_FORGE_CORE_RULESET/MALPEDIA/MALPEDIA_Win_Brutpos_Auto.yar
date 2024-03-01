rule MALPEDIA_Win_Brutpos_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bb6abccd-59b3-5a30-9e67-ccbe498737a5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.brutpos"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.brutpos_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "89d0bc6a7e52ba9f63dface96ebbf483b03be0cbf8144ed32f3b88bf360b4eda"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 59 58 83c004 83e904 8808 }
		$sequence_1 = { 03c2 034508 2938 83e902 75e8 ebd9 5e }
		$sequence_2 = { 8d5b18 8b5b60 03d8 52 8b35???????? }
		$sequence_3 = { 6681f9df77 7412 0f31 8bd8 }
		$sequence_4 = { 8bd0 ad 8bc8 83e908 66ad 6685c0 740c }
		$sequence_5 = { 8d7c38fc baffffffff 83c704 57 }
		$sequence_6 = { 66ad 6685c0 740c 25ff0f0000 03c2 034508 }
		$sequence_7 = { 52 e8???????? 59 8b09 8bd1 }
		$sequence_8 = { c1e202 03d3 8b12 03d0 }
		$sequence_9 = { 8b5508 8b4204 0fb70a 50 51 807401ff97 }

	condition:
		7 of them and filesize <65536
}
