//bem para começar vou colocar aqui as diretrizes do programa, o ultimo cifrador ficou um pouco confuso
//a tentativa de implementar um ui no terminal comeu muito tempo desnecessário

//texto a ser testado:
//      DecipherAESKey2
//      EncryptDecrypt1
//      CipherTextAES24
//      SecureKeyAES256
//senha

//  opção1(128bits)
//      Mj9oTxW5jY5VFbY9
//  opção2(192bits)
//      XHdsHY8ylk0aKOtT0bHv9F6R
//  opção3(256bits)
//      8l2FeSCA2TFavJel6Mwp2f7iWVAsOxrg


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>             //vai adicionar a possibilidade de usar uint8_t uma representação dos bits;
#include <ctype.h>
//add more librarys


//reminder to use SCREAMING_SNAKE_CASE in the define >:) and camelCase in all other uau quanta sabedoria;



//1) declarações

//1.1) defines
#define KEY_OPTION1 128         //chave de 128 bits
#define KEY_OPTION1_LENGHT 16   //lenght senha 128 bits (16 char)

#define KEY_OPTION2 192         //chave de 192 bits
#define KEY_OPTION2_LENGHT 24   //lemght senha 192 bits (24 char)

#define KEY_OPTION3 256         //chave de 256 bits
#define KEY_OPTION3_LENGHT 32   //lenght senha 256 bits (32 char)

#define RPK1 10 //repetições da chave opção 1;
#define RPK2 12 //repetições da chave opção 2;
#define RPK3 14 //repetições da chave opção 3;

#define NUM_C 4 //Num colunas e linhas 16 bytes/128 bits;
#define TAM_C 16 //16 bytes

#define BLOCOS_MAX  1000 //maximo de blocos de 16 bytes

typedef uint8_t Bloco[NUM_C][NUM_C]; //bloco que sofrerá mudanças;

//1.2) declaração sBox

//sbox e sbox reversas tiradas do site:
//      https://asecuritysite.com/subjects/chapter88

static const uint8_t sBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t sBoxReversa[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

//2) trabalhos com struct;

//2.1) definicao struct;

typedef struct{
    Bloco blocos[BLOCOS_MAX];
    size_t blocoAtual;
    size_t posX;
    size_t posY;
} GerenciadorBlocos;

//2.2) definicao  de funcoes;

//2.2.1) inicialização;

void inicializaGerenciador(GerenciadorBlocos* gerenciador) 
{
    gerenciador->blocoAtual=0;
    gerenciador->posX=0;
    gerenciador->posY=0;
    memset(gerenciador->blocos,0,sizeof(gerenciador->blocos));
}

//2.2.2)  adiciona caractere ao bloco;

int adicionarCaractere(GerenciadorBlocos* gerenciador, uint8_t caractere)
{
    if (gerenciador->blocoAtual >=BLOCOS_MAX){
        return -1; //provavelmente nunca ocorrerá por conta do limite absurdo de 1000 blocos mas nunca se sabe oq o maluco vai querer cifrar;
    }
    if (gerenciador->posX>=NUM_C)// chegando no fim da linha pula pra prox linha ;);
    {
        gerenciador->posX=0;
        gerenciador->posY++;
        if (gerenciador->posY>=NUM_C)//->caso chegue ao fim do bloco pula pro prox :D;
        {
            gerenciador->posY=0;
            gerenciador->blocoAtual++;
            if(gerenciador->blocoAtual >= BLOCOS_MAX) //->->caso chegue no fim do array de blocos retornar erro;
            {
                return -1;
            }
        }
    }

    gerenciador->blocos[gerenciador->blocoAtual][gerenciador->posY][gerenciador->posX]= caractere;
    gerenciador->posX++;
    return 0; //sucesso, sossego e paz
}

//2.2.3) todo

//2.3)funcoes para testar funcionamento;

//2.3.1) visualização dos blocos;

void imprimeBlocos(const GerenciadorBlocos* gerenciador){
    for (size_t i = 0; i <= gerenciador->blocoAtual;i++)
    {
        printf("Bloco %zu:\n",i);
        
        for (size_t y = 0; y < NUM_C; y++)
        {
            for (size_t x = 0; x < NUM_C; x++)
        {
            //printf("%c ",gerenciador->blocos[i][y][x]);
            printf("0x%02x ",gerenciador->blocos[i][y][x]);
        }
        printf("\n");
        }
    printf("\n");
    }
}

//3) trabalhos com a mensagem;

//3.1) definicao de funcoes;

//3.1.1 ajuste de tamanho;

char* inflateMsg(char* texto){          //ajusta o texto para poder ser particionado em blocos de 16bytes;
    size_t lenghtOriginal  = strlen(texto);
    size_t tamPreenchimento=16-(lenghtOriginal%16);
    
    if(tamPreenchimento==16){
        
        char* textoRetorno =malloc((lenghtOriginal+1)*sizeof(char));
        if(textoRetorno==NULL){
            return NULL;
        }
        strcpy(textoRetorno,texto);
        return textoRetorno;
    }

    size_t lenghtNovo = lenghtOriginal+tamPreenchimento;
    char* textoRetorno= malloc((lenghtNovo+1)*sizeof(char));
    if(textoRetorno==NULL){
        return NULL;
    }

    strcpy(textoRetorno,texto);
    memset(textoRetorno+lenghtOriginal,'\\',tamPreenchimento); //vou usar backslash por conta do pouco uso pratico em textos
    
    textoRetorno[lenghtNovo]= '\0';

    return textoRetorno;
}

//3.1.2 transforma string em blocos;

void stringParaBlocos(char* texto, GerenciadorBlocos* gerenciador)
{
    for(size_t i= 0;i<strlen(texto);i++)
    {
        if (adicionarCaractere(gerenciador, texto[i])!=0) {
            printf("Erro na adicao de caractere! \n");
            return;
        }
    }
}

//3.1.3 reconstruir string usando blocos;

// Função para reconstruir a string a partir dos blocos

char* reconstruirString(const GerenciadorBlocos* gerenciador){
    size_t totalSize = 0;

    for(size_t i=0; i<=gerenciador->blocoAtual;i++)
    {
        totalSize+=NUM_C*NUM_C;
    }

    char* textoRetorno = malloc((totalSize+1)*sizeof(char));
    
    if(textoRetorno==NULL)
    {
        return NULL;
    }

    char* ptr = textoRetorno;

    for(size_t i = 0; i <= gerenciador->blocoAtual;i++){
        for(size_t y = 0; y < NUM_C; y++){
            for(size_t x = 0; x < NUM_C; x++){
                if(gerenciador->blocos[i][y][x] != '\0'){
                    *ptr++ = gerenciador->blocos[i][y][x];
                }
            }
        }
    }

    *ptr = '\0';
    return textoRetorno;

}


//4) Fases de criptografia do AES (esse vai dar problema)

//4.1)subbytes

//todo encontrar a coordenada na sBox, ex se o valor asc for 0x44, ir na coluna 4 x  linha 4 da sBox, 0xA5 ir na linha 5 coluna 10

//4.1.1 divisor de termo hexadecimal
void hexSplitter (const GerenciadorBlocos  *gerenciador,int i,int y,int x, int *linha, int *coluna)
{   

    uint8_t hexValue = gerenciador->blocos[i][y][x];

    *linha = (hexValue >> 4) & 0x0F;
    *coluna = hexValue & 0x0F;
}

//4.1.2  encontrar a coordenada na sBox (como estou usando um array de char de uma dimensão tenho de realizar um calculo para encontrar a linha)
int sBoxCoordenadas(const GerenciadorBlocos *gerenciador,int i, int y, int x, int *linha, int *coluna)
{
    hexSplitter(gerenciador, i,y,x,linha,coluna);
    int linhaSBox = *linha;
    int colunaSBox = *coluna;
    int resultado=((linhaSBox*16)+(colunaSBox));//localiza  a posição na sBox
    return resultado;//retorna a posição para manipulações
}

//4.1.3 subbytes

//a ideia aqui é trocar o valor de cada um dos termos por suas coordenadas na sbox usando a funcao  sBoxCoordenadas eu pessoalmente quero voltar o resultado uma matriz

GerenciadorBlocos subbytes(GerenciadorBlocos *gerenciador) {
    GerenciadorBlocos blocoRetorno;
    inicializaGerenciador(&blocoRetorno); // Inicializa o blocoRetorno

    //itera sobre os blocos
    for (size_t i = 0; i <= gerenciador->blocoAtual; i++) {
        //itera sobre as linhas e colunas
        for (size_t y = 0; y < NUM_C; y++) {
            for (size_t x = 0; x < NUM_C; x++) {
                int linha, coluna;
                int posicao = sBoxCoordenadas(gerenciador, i, y, x, &linha, &coluna);

                //verifica se a posição é válida
                if (posicao < 0 || posicao >= 256) {
                    fprintf(stderr, "Posição inválida na S-Box: %d\n", posicao);
                    continue;
                }

                //Obtem o valor da sBox
                uint8_t temp = sBox[posicao];
                
                //add o caractere ao blocoRetorno usando a função adicionarCaractere
                if (adicionarCaractere(&blocoRetorno, temp) != 0) {
                    fprintf(stderr, "Erro ao adicionar caractere no bloco de retorno\n");
                    return blocoRetorno; // Retorna o blocoRetorno até o ponto onde ele foi atualizado
                }

                //benchmark() so que local;
                //printf("Bloco[%zu][%zu][%zu]: 0x%02x (Posição S-Box: %d)\n", i, y, x, temp, posicao);
            }
        }
    }
    return blocoRetorno;
}

//4.2 uma aventura chamada shiftrows;

//4.2.1 rows de linha

uint8_t mudancaRow(const GerenciadorBlocos *gerenciador,uint8_t bloco, uint8_t linha, uint8_t coluna){
    uint8_t resultado;
    if (linha!=0)
    {
        if(linha==1)
        {
            if(coluna!=3){
                resultado = gerenciador->blocos[bloco][linha][coluna+1];
            }
            else{
                resultado = gerenciador->blocos[bloco][linha][0];
            }
        }
        if(linha==2){
            if(coluna<2){
                resultado = gerenciador->blocos[bloco][linha][coluna+2];
            }
            else if(coluna>=2){
                resultado = gerenciador->blocos[bloco][linha][coluna-2];
            }
        }
        if(linha==3){
            if(coluna==0){
                resultado = gerenciador->blocos[bloco][linha][3];
            }
            else if(coluna==1){
                resultado = gerenciador->blocos[bloco][linha][0];
            }
            else if(coluna==2){
                resultado = gerenciador->blocos[bloco][linha][1];
            }
            else if(coluna==3){
                resultado = gerenciador->blocos[bloco][linha][2];
            }
        }
    }
    else{
        resultado = gerenciador->blocos[bloco][linha][coluna];
    }
    return resultado;
}

GerenciadorBlocos  shiftrows(const GerenciadorBlocos *gerenciador)
{
    GerenciadorBlocos blocoRetorno;
    inicializaGerenciador(&blocoRetorno);
    
    //itera sobre os blocos primeira linha sem mudanças, segunda linha rotacao 1 byte, terceira linha 2... quarta 3 bytes
    uint8_t temp,temp1,temp2,temp3;

    for (size_t i = 0; i <= gerenciador->blocoAtual;i++)
    {
        for(size_t  y = 0; y < NUM_C; y++)
        {
            for(size_t x = 0; x < NUM_C; x++)
            {
                uint8_t temp=mudancaRow(gerenciador,i,y,x);
                if (adicionarCaractere(&blocoRetorno, temp) != 0) {
                    fprintf(stderr, "Erro ao adicionar caractere no bloco de retorno\n");
                    return blocoRetorno; // Retorna o blocoRetorno até o ponto onde ele foi atualizado
                }
            }
        }

    }
    return  blocoRetorno;
}

//funcao interface (termino algum dia);

void titulo(){
    printf("|7/////////////////////////////////////////////////////////////////////////////////////////////////////////7|\n||                                                                                                         ||\n||    AAAA    EEEEEEEEEE   SSSSSSSS    CCCCCCCCCC YY      YY PPPPPPPP   HH      HH EEEEEEEEEE RRRRRRRR     ||\n||  AA    AA  EE         SS            CC         YY      YY PP      PP HH      HH EE         RR      RR   ||\n||  AA    AA  EE         SS            CC          YY    YY  PP      PP HH      HH EE         RR      RR   ||\n|| AAAAAAAAAA EEEEE       SSSSSSSS     CC           YYYYYY   PPPPPPPP   HHHHHHHHHH EEEEE      RRRRRRRR     ||\n|| AA      AA EE                 SS    CC             YY     PP         HH      HH EE         RR   RR      ||\n|| AA      AA EE                 SS    CC             YY     PP         HH      HH EE         RR     RR    ||\n|| AA      AA EEEEEEEEEE SSSSSSSS      CCCCCCCCCC     YY     PP         HH      HH EEEEEEEEEE RR      RR   ||\n||                                                                                                         ||\n||uma coloboracao eu, eu mesmo e uma playlist de 17 horas                                                  ||\n|7/////////////////////////////////////////////////////////////////////////////////////////////////////////7|\n\n");
    
}
/*

88/////////////////////////////////////////////////////////////////////////////////////////////////////////88
||                                                                                                         ||
||    AAAA    EEEEEEEEEE   SSSSSSSS    CCCCCCCCCC YY      YY PPPPPPPP   HH      HH EEEEEEEEEE RRRRRRRR     ||
||  AA    AA  EE          SS           CC         YY      YY PP      PP HH      HH EE         RR      RR   ||
||  AA    AA  EE         SS            CC          YY    YY  PP      PP HH      HH EE         RR      RR   ||
|| AAAAAAAAAA EEEEE       SSSSSSSS     CC           YYYYYY   PPPPPPPP   HHHHHHHHHH EEEEE      RRRRRRRR     || 
|| AA      AA EE                SS     CC             YY     PP         HH      HH EE         RR   RR      ||
|| AA      AA EE                 SS    CC             YY     PP         HH      HH EE         RR     RR    ||
|| AA      AA EEEEEEEEEE SSSSSSSS      CCCCCCCCCC     YY     PP         HH      HH EEEEEEEEEE RR      RR   ||
||                                                                                                         ||
||uma coloboracao eu, eu mesmo e uma playlist de 17 horas                                                  ||
88/////////////////////////////////////////////////////////////////////////////////////////////////////////88

*/


// funcao benchmark
void benchmark(){//testar se funciona
    GerenciadorBlocos gerenciador;
    inicializaGerenciador(&gerenciador);

    char texto[] = "DecipherAESKeyEncryptDecryptCipherTextAESSecureKeyAES256";
    char* paddedText = inflateMsg(texto);

    if (paddedText != NULL) {
        printf("Texto Original:     '%s'\n", texto);
        printf("Texto Preenchido:   '%s'\n", paddedText);
    } else {
        printf("Memory allocation failed.\n");
    }

    stringParaBlocos(paddedText,&gerenciador);
    imprimeBlocos(&gerenciador);
    free(paddedText);

    



    char* reconstrucao = reconstruirString(&gerenciador);
    printf("Reconstrucao: '%s'\n", reconstrucao);

    int coluna, linha;
    //hexSplitter(&gerenciador, 1, 2, 1, &linha, &coluna);//ta trocado
    int teste =sBoxCoordenadas(&gerenciador, 1, 2, 1, &linha, &coluna);
    printf("Linha: % d\n", linha);  
    printf("Coluna: %d\n", coluna);
    printf("0x%2x",sBox[teste]);

    GerenciadorBlocos bits;
    inicializaGerenciador(&bits);
    bits=subbytes(&gerenciador);
    printf("\nsubbytes:\n");
    imprimeBlocos(&bits);

    GerenciadorBlocos shiftedrows;
    inicializaGerenciador(&shiftedrows);
    shiftedrows=shiftrows(&bits);
    printf("\nshifted rows:\n");
    imprimeBlocos(&shiftedrows);
    free(reconstrucao);
}
//main
int main(){
    titulo();
    printf("colocarei  aqui o menu#FE\n");
    benchmark();
    
    //GerenciadorBlocos gerenciador;
    //inicializaGerenciador(&gerenciador);
    return 0;
}

