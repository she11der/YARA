rule MALPEDIA_Win_Gh0Sttimes_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "edb23d28-51bf-5c0e-a6f1-7bed7d79f2ed"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gh0sttimes"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.gh0sttimes_auto.yar#L1-L163"
		license_url = "N/A"
		logic_hash = "cd1718bc24ef159d263847a726492a25887a81e094fffc2e2f0e4d7ba74c2151"
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
		$sequence_0 = { 899df0fdffff 899decfdffff 889df4fdffff 889df5fdffff 889df6fdffff 889df7fdffff 889df8fdffff }
		$sequence_1 = { 52 50 8985dcfdffff e8???????? }
		$sequence_2 = { 50 ff15???????? 85c0 750f 5b }
		$sequence_3 = { 33c5 8945fc 8b4508 53 33db 8d8de0fdffff 51 }
		$sequence_4 = { 0f852c010000 b8???????? 8d5001 8d642400 }
		$sequence_5 = { 8b0e 51 ff15???????? 43 }
		$sequence_6 = { 6a09 8d4df0 c645f070 8945f5 e8???????? 8b4dfc 5f }
		$sequence_7 = { 0f8638010000 83c708 8b57fc 8b85ecfdffff 52 }
		$sequence_8 = { 488b4c2438 488d442430 488d150c710200 4889442428 }
		$sequence_9 = { 488b4c2438 488d442434 4c8d4c2430 4889442428 488d442440 488d1520790200 }
		$sequence_10 = { 488b8f40010000 ff15???????? 488b8f40010000 ff15???????? 48c78740010000ffffffff }
		$sequence_11 = { 488b4c2430 488b4968 e8???????? 4c8b5c2430 }
		$sequence_12 = { 488b4c2430 83490c08 a808 7409 488b442430 83480c04 }
		$sequence_13 = { 488b4c2430 48c1e80c f7d0 334108 }
		$sequence_14 = { 488b4c2438 488d442430 488d15da700200 4889442428 }
		$sequence_15 = { 488b4c2430 488b4968 33c0 66890451 488b442430 }

	condition:
		7 of them and filesize <548864
}
