package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/wsczx/remlink/dbdata"
)

func UserIpMapList(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	pageS := r.FormValue("page")
	page, _ := strconv.Atoi(pageS)
	if page < 1 {
		page = 1
	}

	var pageSize = dbdata.PageSize

	count := dbdata.CountAll(&dbdata.IpMap{})

	var datas []dbdata.IpMap
	err := dbdata.Find(&datas, pageSize, page)
	if err != nil && !dbdata.CheckErrNotFound(err) {
		RespError(w, RespInternalErr, err)
		return
	}

	// 确保空结果返回 [] 而非 null
	if datas == nil {
		datas = []dbdata.IpMap{}
	}

	data := map[string]interface{}{
		"count":     count,
		"page_size": pageSize,
		"datas":     datas,
	}

	RespSucess(w, data)
}

func UserIpMapDetail(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	idS := r.FormValue("id")
	id, _ := strconv.Atoi(idS)
	if id < 1 {
		RespError(w, RespParamErr, "用户名错误")
		return
	}

	var data dbdata.IpMap
	err := dbdata.One("Id", id, &data)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}

	RespSucess(w, data)
}

func UserIpMapSet(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer r.Body.Close()
	v := &dbdata.IpMap{}
	err = json.Unmarshal(body, v)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}

	err = dbdata.SetIpMap(v)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}

	dbdata.AdminLog("IP映射管理", v.IpAddr, "创建/修改了IP映射", r.RemoteAddr)
	RespSucess(w, nil)
}

func UserIpMapDel(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	idS := r.FormValue("id")
	id, _ := strconv.Atoi(idS)

	if id < 1 {
		RespError(w, RespParamErr, "IP映射id错误")
		return
	}

	var data dbdata.IpMap
	err := dbdata.One("Id", id, &data)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}

	err = dbdata.Del(&data)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}

	dbdata.AdminLog("IP映射管理", data.IpAddr, "删除了IP映射", r.RemoteAddr)
	RespSucess(w, nil)
}
