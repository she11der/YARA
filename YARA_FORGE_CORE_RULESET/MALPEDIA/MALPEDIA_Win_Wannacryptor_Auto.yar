rule MALPEDIA_Win_Wannacryptor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e56d2000-fe42-59bd-8926-478b3a54b7b3"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wannacryptor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.wannacryptor_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "c696b2074a3cd60e9575143d9577c550babed6e9c2f46c424c5b90d1a1647723"
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
		$sequence_0 = { 56 8bf1 57 8b7c241c 8b4670 }
		$sequence_1 = { 8854243c 8b44243c 50 51 8bce }
		$sequence_2 = { b801000000 33ff 85c0 7e76 8bd8 8b5500 03cf }
		$sequence_3 = { 8bce e8???????? 8a4649 84c0 7419 8b4620 }
		$sequence_4 = { ff15???????? 50 e8???????? 85c0 742e 8b4004 8d542404 }
		$sequence_5 = { 8b4674 c6464801 85c0 7509 6a00 }
		$sequence_6 = { 50 ff15???????? 50 e8???????? 8b4820 6a00 6a00 }
		$sequence_7 = { 8b4678 8d7e44 85c0 755f 8b17 }
		$sequence_8 = { e8???????? 8d4648 8d4c2410 50 c744243000000000 }
		$sequence_9 = { 57 8b7c241c 8b4670 85c0 7503 }

	condition:
		7 of them and filesize <540672
}
