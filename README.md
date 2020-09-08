### tinygit

A fork from [pygit](https://github.com/benhoyt/pygit) which implements basic operations of git in pure Python3. 


#### Included

- init
- add
- commit 
- push (to a git server like GitHub)
- status
- diff
- cat-file


#### init 做的事情
创建 .git 和相关文件


#### add 做的事情
根据工作区的变动更新 index
1. 为每个变化的文件创建索引，索引格式为 文件 meta 信息 + 文件 hash + 文件名长度 + 文件路径 
2. 将文件内容以 blob object 保存，路径为 hash
3. 将创建完的所有索引以一定的格式拼起来，写入到索引文件  .git/index 中


##### commit 做的事情
由 index 生成唯一的 tree object，附上作者提交信息等相关内容生成 commit object
1. 将当前文件目录结构保存 (write_tree) ，本质上做的事情是将每个文件的 mode，path，hash 拼起来得到 tree_entry，再将所有 tree_entry 拼起来以 tree object 保存，路径为 hash
2. 拼接 tree object、作者信息、提交者信息、时间、parent、提交信息以 commit object 保存，路径为 hash
3. 最后将 hash 写入 .git/refs/heads/master


#### push 做的事情
对比 local 和 remote 的commit，更新 remote 
1. 首先分别获取本地 master 的 hash，然后解析对应的 commit object，获取 tree object 、parent tree objects 的 hash，然后解析这些 tree objects，最后拿到所有 blob object 的 hash，最后返回一个 hash set。同样的，对 remote master hash 也做同样的事情，得到一个 hash set
2. 比较两个 hash set 得出本地和 remote 的差别
3. 根据差别的 hash 去找对应的文件，将其打包起来最后发送给 server 
