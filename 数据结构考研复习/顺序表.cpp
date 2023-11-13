/*
author: Mz1
mzi_mzi@163.com
date: 2022.6.11 

*/

#include "mzdatastruct.h"

// 用于测试数据结构 
typedef int ElemType;

// 存储结构
#define MAXSIZE 100
typedef struct{
	ElemType* elem;         // 存储空间的基地址
	int length;             // 当前长度 
}SqList;                    // 顺序表结构类型为Sqlist 



// 顺序表的初始化
Status InitList(SqList &L){
	// 构造一个空的顺序表L
	L.elem = new ElemType[MAXSIZE];          // 为顺序表分配堆空间 
	if(!L.elem) exit(OVERFLOW);             // 存储分配失败退出 
	L.length = 0;
	return OK; 
}

// 顺序表取值
Status GetElem(SqList L, int i, ElemType &e){
	if (i<1||i>L.length) return ERROR;
	e = L.elem[i-1];              // 数据结构的反人类写法index从1开始 
	return OK;
} 

// 顺序表查找
int LocateElem(SqList L, ElemType e){
	int i;
	for (i = 0; i < L.length; i++){
		if (L.elem[i] == e) return i+1;        // 反人类写法下标从1开始 
	}
	return 0;             // 查找失败 
} 

// 顺序表插入
Status ListInsert(SqList &L, int i, ElemType e){
	// 在顺序表第i个位置插入新的元素e，i的合法范围是1<=i<=L.length+1
	int j;
	if ((i<1)||(i>L.length+1)) return ERROR;    // i值不合法
	if (L.length == MAXSIZE) return ERROR;    // 存储空间满了
	for  (j = L.length-1; j>=i-1; j --) L.elem[j+1] = L.elem[j];          // 将插入位置之后的元素向后移动 
	L.elem[i-1] = e;
	++L.length;
	return OK;
} 

// 顺序表删除
Status ListDelete(SqList &L, int i){
	// 在顺序表中删除第i个元素，合法范围如下
	int j;
	if ((i<1)||(i>L.length)) return ERROR;
	for (j = i; j<=L.length-1; j ++){
		L.elem[j-1] = L.elem[j];
	} 
	--L.length;
	return OK;
} 

// 输出线性表
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
	InitList(L);   // 初始化
	for (i = 1; i <= 10; i ++){        // 向表中插入数据
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
