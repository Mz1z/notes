/*
author: Mz1
mzi_mzi@163.com
date: 2022/6/11
*/

#include "mzdatastruct.h"

// 用于测试数据结构 
typedef int ElemType;

//含有头结点 
typedef struct LNode
{
	ElemType data;           // 节点数据域
	struct LNode* next;        // 节点的指针域 
}LNode, *LinkList;         // LinkList为指向结构体LNode的指针类型 

// 初始化
Status InitList(LinkList &L){
	// 构造一个空的单链表L
	L = new LNode;         // 生成新节点作为头结点，用头指针L指向头结点
	L->next = NULL;         // 将头结点指针域置空
	return OK;	
} 

// 单链表的取值
Status GetElem(LinkList L, int i, ElemType &e){
	// 在带头结点的单链表L中根据序号i获取元素的值, 用e返回
	LNode* p;       // 临时节点
	int j;
	p = L->next;
	j = 1;
	while (p && j<i){
		p = p->next;
		++j;
	} 
	if (!p || j>i) return ERROR;    // 如果p为空或者i有问题，则返回错误
	e = p->data;
	return OK; 
} 

// 单链表的查找
LNode* LocateElem(LinkList L, ElemType e){
	// 在带头结点的单链表L中查找值为e的元素
	LNode* p;
	p = L->next;
	while (p && p->data!=e){
		p = p->next;
	}
	return p;        // 查找成功返回地址，查找失败p=NULL 
} 

// 单链表的插入
Status ListInsert(LinkList &L, int i, ElemType e){
	// 在带头结点的单链表L的第i个位置插入值为e的节点
	LNode* p;
	LNode* s;        // 新的节点 
	int j;
	while (p && (j<i-1)){
		// 先过到第i-1个节点
		p = p->next;
		++j;
	} 
	if (!p || j>i-1) return ERROR;     // i超过总长度或者i<1
	// 创建一个新的节点
	s = new LNode;
	s->data = e;
	s->next = p->next;
	p->next = s;
	return OK; 
} 

// 删除
Status ListDelete(LinkList &L, int i){
	// 删除第i个元素
	LNode* p;
	LNode* q;       // 临时保存要删除的节点 
	int j;
	while(p && (j<(i-1))){
		p = p->next;
		++j;
	} 
	if ((p->next) || (j>(i-1))) return ERROR;    // 位置不合理
	q = p->next;
	p->next = q->next;
	delete q;
	return OK;
} 


// 前插法创建单链表
void CreateList_H(LinkList &L, int n){
	// 逆序输入n个元素的值，建立表头节点的单链表L
	L = new LNode;
	L->next = NULL;
	int i;
	LNode* p;
	for (i = 0; i < n; i ++){
		p = new LNode;
		scanf("%d", &p->data);
		p->next = L->next;
		L->next = p;              // 将新节点插入到头结点之后 
	} 
} 

// 后插法
void CreateList_R(LinkList &L, int n){
	// 正序输入n个元素的值
	L = new LNode;
	L->next = NULL;
	int i;
	LNode* p;
	LNode* r;
	r = L;           // r用来一直指向最后一个节点 
	for (i = 0; i < n; i ++){
		p = new LNode;
		scanf("%d", &p->data);
		p->next = NULL;
		r->next = p;
		r = p;             // r->next指向新节点，r=新节点，这样r就又是尾节点了。		
	} 
} 


// =============================================
// mz
void PrintList(LinkList L){
	LNode* p;
	int i;
	p = L->next;
	printf("=======================\n");
	while(p){
		i++;
		printf("[%d] %d \n", i, p->data);
		p = p->next;
	}
	printf("=======================\n");
} 

int main(){
	LinkList L;          // 创建一个新的单链表
	// InitList(L);         // 初始化 
	CreateList_H(L, 5);        // 前插法 
	PrintList(L);
	
	CreateList_R(L, 5);    // 后插法 
	PrintList(L);
	return 0;
}












