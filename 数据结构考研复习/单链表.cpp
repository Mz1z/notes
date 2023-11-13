/*
author: Mz1
mzi_mzi@163.com
date: 2022/6/11
*/

#include "mzdatastruct.h"

// ���ڲ������ݽṹ 
typedef int ElemType;

//����ͷ��� 
typedef struct LNode
{
	ElemType data;           // �ڵ�������
	struct LNode* next;        // �ڵ��ָ���� 
}LNode, *LinkList;         // LinkListΪָ��ṹ��LNode��ָ������ 

// ��ʼ��
Status InitList(LinkList &L){
	// ����һ���յĵ�����L
	L = new LNode;         // �����½ڵ���Ϊͷ��㣬��ͷָ��Lָ��ͷ���
	L->next = NULL;         // ��ͷ���ָ�����ÿ�
	return OK;	
} 

// �������ȡֵ
Status GetElem(LinkList L, int i, ElemType &e){
	// �ڴ�ͷ���ĵ�����L�и������i��ȡԪ�ص�ֵ, ��e����
	LNode* p;       // ��ʱ�ڵ�
	int j;
	p = L->next;
	j = 1;
	while (p && j<i){
		p = p->next;
		++j;
	} 
	if (!p || j>i) return ERROR;    // ���pΪ�ջ���i�����⣬�򷵻ش���
	e = p->data;
	return OK; 
} 

// ������Ĳ���
LNode* LocateElem(LinkList L, ElemType e){
	// �ڴ�ͷ���ĵ�����L�в���ֵΪe��Ԫ��
	LNode* p;
	p = L->next;
	while (p && p->data!=e){
		p = p->next;
	}
	return p;        // ���ҳɹ����ص�ַ������ʧ��p=NULL 
} 

// ������Ĳ���
Status ListInsert(LinkList &L, int i, ElemType e){
	// �ڴ�ͷ���ĵ�����L�ĵ�i��λ�ò���ֵΪe�Ľڵ�
	LNode* p;
	LNode* s;        // �µĽڵ� 
	int j;
	while (p && (j<i-1)){
		// �ȹ�����i-1���ڵ�
		p = p->next;
		++j;
	} 
	if (!p || j>i-1) return ERROR;     // i�����ܳ��Ȼ���i<1
	// ����һ���µĽڵ�
	s = new LNode;
	s->data = e;
	s->next = p->next;
	p->next = s;
	return OK; 
} 

// ɾ��
Status ListDelete(LinkList &L, int i){
	// ɾ����i��Ԫ��
	LNode* p;
	LNode* q;       // ��ʱ����Ҫɾ���Ľڵ� 
	int j;
	while(p && (j<(i-1))){
		p = p->next;
		++j;
	} 
	if ((p->next) || (j>(i-1))) return ERROR;    // λ�ò�����
	q = p->next;
	p->next = q->next;
	delete q;
	return OK;
} 


// ǰ�巨����������
void CreateList_H(LinkList &L, int n){
	// ��������n��Ԫ�ص�ֵ��������ͷ�ڵ�ĵ�����L
	L = new LNode;
	L->next = NULL;
	int i;
	LNode* p;
	for (i = 0; i < n; i ++){
		p = new LNode;
		scanf("%d", &p->data);
		p->next = L->next;
		L->next = p;              // ���½ڵ���뵽ͷ���֮�� 
	} 
} 

// ��巨
void CreateList_R(LinkList &L, int n){
	// ��������n��Ԫ�ص�ֵ
	L = new LNode;
	L->next = NULL;
	int i;
	LNode* p;
	LNode* r;
	r = L;           // r����һֱָ�����һ���ڵ� 
	for (i = 0; i < n; i ++){
		p = new LNode;
		scanf("%d", &p->data);
		p->next = NULL;
		r->next = p;
		r = p;             // r->nextָ���½ڵ㣬r=�½ڵ㣬����r������β�ڵ��ˡ�		
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
	LinkList L;          // ����һ���µĵ�����
	// InitList(L);         // ��ʼ�� 
	CreateList_H(L, 5);        // ǰ�巨 
	PrintList(L);
	
	CreateList_R(L, 5);    // ��巨 
	PrintList(L);
	return 0;
}












