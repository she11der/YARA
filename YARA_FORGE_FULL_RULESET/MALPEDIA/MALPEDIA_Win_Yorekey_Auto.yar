rule MALPEDIA_Win_Yorekey_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0c2854a9-311b-528a-8d3c-9008975025f5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yorekey"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.yorekey_auto.yar#L1-L165"
		license_url = "N/A"
		logic_hash = "bfaa0e3abe9f69e663c8e7749df7b846bcbaa395b01b91bd4c5c56f646e51121"
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
		$sequence_0 = { 750a 85c0 7506 ff15???????? }
		$sequence_1 = { 4883ec20 33ff 488d1dc9fa0000 488b0b ff15???????? }
		$sequence_2 = { 33c9 ff15???????? 488bd8 ff15???????? 3db7000000 7509 }
		$sequence_3 = { 8bc6 83f801 7521 a1???????? 50 ff15???????? 68???????? }
		$sequence_4 = { 03048de0404100 eb02 8bc2 f6402480 0f8571ffffff 33f6 3bfe }
		$sequence_5 = { 4803d1 488d0d02090100 442bc6 488b0cc1 498b0c0c ff15???????? 85c0 }
		$sequence_6 = { 7530 a1???????? ba???????? 50 e9???????? a1???????? }
		$sequence_7 = { 488bce e8???????? 488d154c040100 4c63c8 418d4902 }
		$sequence_8 = { 730d 488bd3 488bcf e8???????? eb1c }
		$sequence_9 = { 751b 6a02 33c9 51 }
		$sequence_10 = { 7405 6641894d00 4885f6 7457 483bf7 7252 4d85ff }
		$sequence_11 = { 898570ffffff 89856cffffff 8d4598 b919000000 }
		$sequence_12 = { ff15???????? 488d44243c 448d4f04 4889442428 4c8d05cbfaffff }
		$sequence_13 = { 5a 8985c4fbffff 3bc2 0f8451ffffff 83f807 0f87110a0000 ff2485b19b4000 }
		$sequence_14 = { 55 8bec 51 8bc2 56 8d7002 8d9b00000000 }

	condition:
		7 of them and filesize <274432
}
