package main

import (
	"fmt"
	"strconv"
	"io/ioutil"
	"os"
)


var S0  = [4][4]int{ {1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2} }
var S1  = [4][4]int{ {0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3} }
var mode = true

const (
	help = "Command Option : \n Encryption:  ./lab1 -en -in InputFile -k 10bitParentKey -iv InitialVector \n Decryption:  ./lab1 -de -in InputFile -k 10bitParentKey -iv InitialVector"
)



//////////////////////////////////////////////////////////////////////////

func formatBin8(bin string) string {
	if len(bin) == 8 {
		return bin
	}  else {
		return formatBin8("0" + bin)
	}
}
func formatBin2(bin string) string {
	if len(bin) == 2 {
		return bin
	}  else {
		return formatBin2("0" + bin)
	}
}
func StringToByte(input string) byte{
	res,err := strconv.ParseInt(input,2,64)
	if err != nil {
		panic(0)
	} else {
		return uint8(res)
	}
}

func XOR(s1 string, s2 string) string{
	result := ""
	if len(s1) != len(s2){
		panic(nil)
	} else {
		for i:=0;i<len(s1);i++{
			if s1[i] != s2[i] {
				result = result + "1"
			} else {
				result = result + "0"
			}
		}
	}
	return result
}
// Key generate function

func CLS(input string, round int) string {
	var result string
	for i:=1; i<=round; i++{
		result = string(input[1])
		for j:=2; j<len(input);j++{
			result = result + string(input[j])
		}
		result = result + string(input[0])
		input = result
	}
	return result
}

func P10(input string) string {
	return string(input[2])+string(input[4])+string(input[1])+string(input[6])+string(input[3])+string(input[9])+string(input[0])+string(input[8])+string(input[7])+string(input[5])
}
func P8(input string) string {
	return string(input[5])+string(input[2])+string(input[6])+string(input[3])+string(input[7])+string(input[4])+string(input[9])+string(input[8])
}

func keygenerator (parent string) (k1 string, k2 string){
	if len(parent) != 10 {
		panic(nil)
	}
	k1 = P8(CLS(P10(parent)[:5],1) + CLS(P10(parent)[5:],1))
	k2 = P8(CLS(P10(parent)[:5],3) + CLS(P10(parent)[5:],3))
	return
}

//  SDES algorithm
func IP(bin string) string {
	resbin := string(bin[1])+string(bin[5])+string(bin[2])+string(bin[0])+string(bin[3])+string(bin[7])+string(bin[4])+string(bin[6])
	return resbin
}

func fP(bin string) byte{
	resbin := string(bin[3])+string(bin[0])+string(bin[2])+string(bin[4])+string(bin[6])+string(bin[1])+string(bin[7])+string(bin[5])
	resInt, _ := strconv.ParseInt(resbin, 2, 64)
	return uint8(resInt)
}
func EP(input string) string {
	return string(input[3])+string(input[0])+string(input[1])+string(input[2])+string(input[1])+string(input[2])+string(input[3])+string(input[0])
}
func P4(input string) string {
	return string(input[1]) + string(input[3]) + string(input[2]) + string(input[0])
}
func Fmap(input string, key string) string{
	left, right := XOR(EP(input), key)[:4], XOR(EP(input), key)[4:]

	rowS0, _ := strconv.ParseInt(string(left[0]) + string(left[3]),2,64)
	colS0, _ := strconv.ParseInt(string(left[1]) + string(left[2]),2,64)

	rowS1, _ := strconv.ParseInt(string(right[0]) + string(right[3]),2,64)
	colS1, _ := strconv.ParseInt(string(right[1]) + string(right[2]),2,64)

	s0res := formatBin2(strconv.FormatInt(int64(S0[int(rowS0)][int(colS0)]),2))
	s1res := formatBin2(strconv.FormatInt(int64(S1[int(rowS1)][int(colS1)]),2))
	return P4(s0res + s1res)
}

func FK(block string, key string) string {
	left, right := block[:4], block[4:]
	return XOR(left,Fmap(right, key)) + right
}

// S-DES encryption
func SW (input string) string {
	return string(input[4])+string(input[5])+string(input[6])+string(input[7])+string(input[0])+string(input[1])+string(input[2])+string(input[3])
}

func SDESen(input []byte, output *[]byte, parentKey string, iv string) {
	key1, key2 := keygenerator(parentKey)
	for _, block := range input {
		blockBin := formatBin8(strconv.FormatInt(int64(block),2))
		applyIV := XOR(blockBin,iv)
		step1 := IP(applyIV)
		step2 := FK(step1, key1)
		step3 := SW(step2)
		step4 := FK(step3, key2)
		step5 := fP(step4)
		iv = formatBin8(strconv.FormatInt(int64(step5),2))
		*output = append(*output, step5 )
	}
}

// S-DES decryption

func deIP( input string ) byte {
	resString := string(input[3])+string(input[0])+string(input[2])+string(input[4])+string(input[6])+string(input[1])+string(input[7])+string(input[5])
	resInt,_ := strconv.ParseInt(resString, 2, 64)
	return uint8(resInt)
}

func defP( input byte ) string{
	binString := formatBin8(strconv.FormatInt(int64(input),2))
	return string(binString[1])+string(binString[5])+string(binString[2])+string(binString[0])+string(binString[3])+string(binString[7])+string(binString[4])+string(binString[6])
}

func deSW(input string) string{
	return input[4:]+input[:4]
}

func deFK(block string, key string) string {
	left, right := block[:4], block[4:]
	return XOR(left,Fmap(right, key)) + right
}

func SDESde(input []byte, output *[]byte, parentKey string, iv string) {
	key1, key2 := keygenerator(parentKey)
	for _, block := range input {
		step1 := defP(block)
		step2 := deFK(step1, key2)
		step3 := deSW(step2)
		step4 := deFK(step3, key1)
		step5 := deIP(step4)
		applyIV := XOR(formatBin8(strconv.FormatInt(int64(step5),2)),iv)
		iv = formatBin8(strconv.FormatInt(int64(block),2))
		*output = append(*output, StringToByte(applyIV))
	}
}

func main() {

	// check pass in arguments

	args := os.Args[1:]
	var inputFile, parentKey, initialVector string
	if len(args) != 7 {
		fmt.Println(help)
		os.Exit(0)
	} else {
		for j:=0;j<len(args); {
			switch args[j] {
			case "-en":
				mode = true
				j++
				continue
			case "-de":
				mode = false
				j++
				continue
			case "-in":
				inputFile = args[j+1]
			case "-k":
				parentKey = args[j+1]
				_, err := strconv.ParseInt(parentKey,2,64)
				if len(parentKey)!=10 || err != nil {
					fmt.Println("Wrong Parent key syntax, please use a 10 binaries bit parent key")
					os.Exit(0)
				}
			case "-iv":
				initialVector = args[j+1]
				_, err := strconv.ParseInt(initialVector,2,64)
				if len(initialVector)!=8 || err != nil {
					fmt.Println("Wrong Initial Vector syntax, please use an 8 binaries bit Initial Vector")
					os.Exit(0)
				}
			default :
				fmt.Println(help)
				os.Exit(0)
			}
			j+=2
		}

	}

	inputData, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Println("Input File Not Exist")
		os.Exit(0)
	}
	if mode {
		var outputEn []byte
		SDESen(inputData, &outputEn, parentKey, initialVector)
		ioutil.WriteFile("result_ciphertext.txt", outputEn, 0644)
		fmt.Println("Encryption Done\nInput:",inputFile,"\nKey:",parentKey,"\nIV:",initialVector,"\nOutput:","result_ciphertext.txt")
	} else {
		var outputDe []byte
		SDESde(inputData, &outputDe, parentKey, initialVector)
		ioutil.WriteFile("plaintext.txt", outputDe, 0644)
		fmt.Println("Decryption Done\nInput:",inputFile,"\nKey:",parentKey,"\nIV:",initialVector,"\nOutput:","plaintext.txt")
	}
}
