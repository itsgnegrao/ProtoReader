/**

UTFPR (Universidade Tecnologica Federal do Parana)
Disciplina: Redes de Computadores 2
Autor: Gabriel Negrão Silva
RA: 1602012

**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ethernetProtocol(char* buffer){
    printf("\nETHERNET PROTOCOL:\n");
    printf("Mac Destino: ");
    printf("%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]); ///Lê 6 bytes do endereco mac de destino

    printf("\nMac Origem: ");
    printf("%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",buffer[6],buffer[7],buffer[8],buffer[9],buffer[10],buffer[11]);///Lê 6 bytes do endereco mac de origem

    printf("\nTipo: %02hhX%02hhX",buffer[12],buffer[13]); ///Lê 2 bytes para verificar o tipo do protocolo ethernet

}

int ipProtocol(char* buffer){
    printf("\n\nIP PROTOCOL:\n");

    printf("Tipo: %d \n", buffer[14]>>4); ///Lê 4 bits para verificar o tipo

    printf("Header Length: %d bytes \n", ((buffer[14] & 0x0F)*32)/8);///Lê o ultimos 4 bits para header lenght

    printf("Tipo de Servico: %d \n", buffer[15] & 0xFF);/// lê 1 byte para verificar o tipo de servico

    int tt = buffer[16] & 0xFF;
    tt = tt <<8;
    tt|= buffer[17] & 0xFF;
    printf("Tamanho Total: %d \n", tt); ///Lê 2 bytes e concatena o numero de 16 bits

    printf("Identificação: 0x%02hhX%02hhX \n", (buffer[18] & 0xFF),(buffer[19] & 0xFF)); ///Lê 2 bytes em Hex de 16 bits

    printf("Flags: %02hhX \n", buffer[20]>>3);///Lê os 3 primeiros bits para as FLags

    printf("Fragment Offset: %02hhX%02hhX \n", buffer[20] & 0x1F, buffer[21]);///Lê os 7 ultimos bits e mais 1 byte para as Fragment offset

    printf("TTL: %d \n", buffer[22]);///Lê um numero de 1 byte (8 bits) para ttl

    printf("Protocol: %d \n", buffer[23]);///Lê um numero de 1 byte (8 bits) para Protocolo

    printf("Header Checksum: 0x%02hhX%02hhX \n", (buffer[24] & 0xFF),(buffer[25] & 0xFF));///Lê um numero de 2 bytes em Hex para Checksum

    printf("IP Origem: %d:%d:%d:%d\n", (buffer[26] & 0xFF),(buffer[27] & 0xFF),(buffer[28] & 0xFF),(buffer[29] & 0xFF)); ///Lê o endereço IP origem de 4 bytes

    printf("IP Destino: %d:%d:%d:%d\n", (buffer[30] & 0xFF),(buffer[31] & 0xFF),(buffer[32] & 0xFF),(buffer[33] & 0xFF)); ///Lê o endereço IP destino de 4 bytes


    return buffer[23]; ///retorna o tipo do protocolo UDP/TCP
}

void udpProtocol(char* buffer){
    printf("\n\nUDP PROTOCOL:\n");

    int po = buffer[34] & 0xFF;
    po = po << 8;
    po|= buffer[35] & 0xFF;
    printf("Porta Origem: %d \n", po);///Lê o numero de 2 bytes e concatena parte baixa e alta para porta de origem

    int pd = buffer[36] & 0xFF;
    pd = pd <<8;
    pd|= buffer[37] & 0xFF;
    printf("Porta Destino: %d \n", pd);///Lê o numero de 2 bytes e concatena parte baixa e alta para porta de destino

    int len = buffer[38] & 0xFF;
    len = len <<8;
    len|= buffer[39] & 0xFF;
    printf("Length: %d \n", len);///Lê o numero de 2 bytes e concatena parte baixa e alta para Length

    printf("Checksum: 0x%02hhX%02hhX \n", (buffer[40] & 0xFF),(buffer[41] & 0xFF));///Lê o numero de 2 bytes em Hex para Checksum
}

void tcpProtocol(char* buffer){
    printf("\n\nTCP PROTOCOL:\n");

    int po = buffer[34] & 0xFF;
    po = po <<8;
    po|= buffer[35] & 0xFF;
    printf("Porta Origem: %d \n", po);///Lê o numero de 2 bytes e concatena parte baixa e alta para porta de origem

    int pd = buffer[36] & 0xFF;
    pd = pd <<8;
    pd|= buffer[37] & 0xFF;
    printf("Porta Destino: %d \n", pd);///Lê o numero de 2 bytes e concatena parte baixa e alta para porta de destino

    printf("Sequence Number: 0x%02hhX%02hhX%02hhX%02hhX  \n", (buffer[38] & 0xFF),(buffer[39] & 0xFF),(buffer[40] & 0xFF),(buffer[41] & 0xFF));///Lê o numero de 4 bytes em Hex para Sequence number

    printf("ACK Number: 0x%02hhX%02hhX%02hhX%02hhX  \n", (buffer[42] & 0xFF),(buffer[43] & 0xFF),(buffer[44] & 0xFF),(buffer[45] & 0xFF));///Lê o numero de 4 bytes em Hex para ACK number

    int hl = (buffer[46] & 0xF0);
    hl = hl>>4;
    printf("Header Length: %d bytes\n", hl*4);///Lê os primeiros 4 bits e multiplica o resultado por 4 para dar o tamanho em bytes

    printf("Flags: 0x%02hhX \n", buffer[47]);///Lê 1 byte para as flags

    int ws = buffer[48] & 0xFF;
    ws = ws <<8;
    ws|= buffer[49] & 0xFF;
    printf("Window Size: %d \n", ws);///Lê o numero de 2 bytes e concatena parte baixa e alta para window size

    printf("Checksum: 0x%02hhX%02hhX \n", (buffer[50] & 0xFF),(buffer[51] & 0xFF));///Lê o numero de 2 bytes em Hex para Checksum

    printf("Urgent Pointer: %d \n", (buffer[53] | buffer[52] << 8));///Lê o numero de 2 bytes para Urgent Pointer
}

int main(int argc, char *argv[]) {
  FILE * pFile;
  long lSize;
  char * buffer;
  size_t result;

  ///Alocação do arquivo e carregamento do mesmo
  pFile = fopen (argv[1], "rb" );
  if (pFile==NULL) {fputs ("Arquivo Não Encontrado!\n",stderr); exit (1);}

  fseek (pFile , 0 , SEEK_END);
  lSize = ftell (pFile);
  rewind (pFile);

  ///Aloca o buffer com o conteúdo do arquivo
  buffer = (char*) malloc (sizeof(char)*lSize);
  if (buffer == NULL) {fputs ("Memory error\n",stderr); exit (2);}

  result = fread (buffer,1,lSize,pFile);
  if (result != lSize) {fputs ("Reading error\n",stderr); exit (3);}

  fclose (pFile);
  printf("Fim da Leitura e Alocação do Arquivo.\n\n");

  ethernetProtocol(buffer); ///funcao de analise do protocolo ethernet
  int protocol = ipProtocol(buffer); /// funcao de analise do protocolo ip
  if(protocol == 6) tcpProtocol(buffer); ///funcao de analise do protocolo tcp
  else if(protocol == 17) udpProtocol(buffer);///funcao de analise do protocolo udp

  printf("\nFim da Analise do Arquivo.\n");
  free (buffer);

  return 0;
}
