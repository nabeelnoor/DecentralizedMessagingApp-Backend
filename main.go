package main //purpose is to make rest api in golang

import (
	hbl "Rest/pk/BLHandler"
	b "Rest/pk/Book"
	hb "Rest/pk/Handlers"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/gorilla/mux"
)

func Recv() {
	temp := "Send from Rest to Test"
	// log.Println("main2")
	// go peerSender()
	ln, err := net.Listen("tcp", ":6000")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
		} else {
			conn.Write([]byte(temp))
		}
	}

}

func Send() {
	buf2 := make([]byte, 4096)
	conn, _ := net.Dial("tcp", ":6001")
	conn.Read(buf2)
	// log.Println(err)
	log.Println("Message:", string(buf2))
}

func Controller() {
	var tempInput string

	for {
		log.Println("1 for close ,2 for send ,3 for start server")
		fmt.Scanln(&tempInput)
		if tempInput == "1" {
			break
		} else if tempInput == "2" {
			go Send()
		} else if tempInput == "3" {
			go Recv()
		}
	}
}

func main() {
	var temp b.Book
	temp.Id = 123
	router := mux.NewRouter()

	//registeration user case
	router.HandleFunc("/registeration", hbl.GetGeneratedKeys).Methods(http.MethodGet) //to get public and private keys
	router.HandleFunc("/storeIdentity", hbl.StoreIdentity).Methods(http.MethodPost)   //test encrypt and decrypt

	router.HandleFunc("/", hbl.Greet).Methods(http.MethodGet)           //get api
	router.HandleFunc("/bl", hbl.GetBlockChain).Methods(http.MethodGet) //get api
	router.HandleFunc("/books", hb.GetAllBooks).Methods(http.MethodGet) //get api
	// router.HandleFunc("/books/{id}", hb.GetBook).Methods(http.MethodGet) //get book by id ,, localhost:4000/1
	router.HandleFunc("/books/id", hb.GetBook2).Methods(http.MethodGet)        //get book by id ,another way to do it  ,e.g such as localhost:4000/books/id?val=1&val2=23
	router.HandleFunc("/addbooks", hb.AddBook).Methods(http.MethodPost)        //post api      method :post   localhost:4000/addbooks   body {		"title": "barium ",		 "author":"abcasdasd",		 "desc":"abc"	}
	router.HandleFunc("/updatebook", hb.UpdateBook).Methods(http.MethodPut)    //update api   method:put 	   localhost:4000/updatebook?bookID=81   body {		"title": "barium update",		 "author":"up",		 "desc":"update- abc"	}
	router.HandleFunc("/deletebook", hb.DeleteBook).Methods(http.MethodDelete) //delete api   method: delete   localhost:4000/deletebook?bookID=81

	// router.HandleFunc("/books", func(w http.ResponseWriter, r *http.Request) {
	// 	json.NewEncoder(w).Encode("Hello World")
	// })

	log.Println("API is running!")
	go Controller()
	http.ListenAndServe(":4000", router) //created for handling of rest apis
	log.Println("API is closed!")
}

/*
special thanks to this article:
https://dev.to/karanpratapsingh/build-a-rest-api-with-go-for-beginners-3gp
*/
