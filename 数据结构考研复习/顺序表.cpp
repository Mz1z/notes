/*
author: Mz1
mzi_mzi@163.com
date: 2022.6.11 

*/

#include "mzdatastruct.h"

// ���ڲ������ݽṹ 
typedef int ElemType;

// �洢�ṹ
#define MAXSIZE 100
typedef struct{
	ElemType* elem;         // �洢�ռ�Ļ���ַ
	int length;             // ��ǰ���� 
}SqList;                    // ˳���ṹ����ΪSqlist 



// ˳���ĳ�ʼ��
Status InitList(SqList &L){
	// ����һ���յ�˳���L
	L.elem = new ElemType[MAXSIZE];          // Ϊ˳������ѿռ� 
	if(!L.elem) exit(OVERFLOW);             // �洢����ʧ���˳� 
	L.length = 0;
	return OK; 
}

// ˳���ȡֵ
Status GetElem(SqList L, int i, ElemType &e){
	if (i<1||i>L.length) return ERROR;
	e = L.elem[i-1];              // ���ݽṹ�ķ�����д��index��1��ʼ 
	return OK;
} 

// ˳������
int LocateElem(SqList L, ElemType e){
	int i;
	for (i = 0; i < L.length; i++){
		if (L.elem[i] == e) return i+1;        // ������д���±��1��ʼ 
	}
	return 0;             // ����ʧ�� 
} 

// ˳������
Status ListInsert(SqList &L, int i, ElemType e){
	// ��˳����i��λ�ò����µ�Ԫ��e��i�ĺϷ���Χ��1<=i<=L.length+1
	int j;
	if ((i<1)||(i>L.length+1)) return ERROR;    // iֵ���Ϸ�
	if (L.length == MAXSIZE) return ERROR;    // �洢�ռ�����
	for  (j = L.length-1; j>=i-1; j --) L.elem[j+1] = L.elem[j];          // ������λ��֮���Ԫ������ƶ� 
	L.elem[i-1] = e;
	++L.length;
	return OK;
} 

// ˳���ɾ��
Status ListDelete(SqList &L, int i){
	// ��˳�����ɾ����i��Ԫ�أ��Ϸ���Χ����
	int j;
	if ((i<1)||(i>L.length)) return ERROR;
	for (j = i; j<=L.length-1; j ++){
		L.elem[j-1] = L.elem[j];
	} 
	--L.length;
	return OK;
} 

// ������Ա�
// @Mz1
void PrintList(SqList L){
	int i;
	printf("[");
	for (i = 0; i < L.length; i ++){
		printf(" %d,", L.elem[i]);
	}
	printf("] \n");
} 

int main(){
	int i; int e;
	SqList L;
	InitList(L);   // ��ʼ��
	for (i = 1; i <= 10; i ++){        // ����в�������
		scanf("%d", &e);
		ListInsert(L, i, e); 
		PrintList(L);
	}
	scanf("%d", &e);
	printf("Locate: %d \n", LocateElem(L, e));
	
	scanf("%d", &i);
	GetElem(L,i, e);
	printf("Delete: index %d: %d \n", i, e);
	ListDelete(L, i);
	PrintList(L);
	
	
	
	return 0;	
}
