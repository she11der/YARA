rule MALPEDIA_Win_Colibri_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "92334149-98b7-5fb0-8e08-056f3f401efb"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.colibri"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.colibri_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "70a6e8c65b49a36e967be3c5e646c3791445447505e2691dc2dc449a828d2e49"
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
		$sequence_0 = { 8b4dfc 8d4901 e8???????? 56 56 8bd8 }
		$sequence_1 = { 0f4575f4 59 e8???????? ba1f90113c 8bc8 e8???????? ffd0 }
		$sequence_2 = { 83c602 0fb706 8bd0 6685c0 75e2 8933 33c0 }
		$sequence_3 = { 8bf1 8bfa 897df8 85f6 7502 }
		$sequence_4 = { 897c2440 57 eba2 8364243c00 eb1b }
		$sequence_5 = { 8d8578f9ffff 33ff 6804010000 50 57 6a02 59 }
		$sequence_6 = { 8365f800 50 e8???????? 59 85c0 7413 8b4dfc }
		$sequence_7 = { 668945a4 6689855effffff 66894d96 59 6a76 58 6a69 }
		$sequence_8 = { 7445 8b4878 85c9 743e 33ff 39787c 7437 }
		$sequence_9 = { c1e81f 8d0448 8b0c85c0124000 8d45d4 }

	condition:
		7 of them and filesize <51200
}