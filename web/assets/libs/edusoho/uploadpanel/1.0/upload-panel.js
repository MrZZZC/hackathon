define(function(require, exports, module) {

    require('swfupload');
    var Widget = require('widget');
    var ChunkUpload = require('./chunk-upload');
    var UploadProgressBar = require('./upload-progress-bar');
    var Notify = require('common/bootstrap-notify');

    var UploadPanel = Widget.extend({
        attrs: {
            uploader: null,
            uploaderSettings: {},
            preUpload: null,
            uploaderProgressbar: null,
            chooser: null
        },

        _convertFileToMedia: function(file) {
            var media = {};
            media.id = file.id ? file.id : 0;
            media.status = file.convertStatus ? file.convertStatus : 'none';
            media.type = file.type;
            media.source = 'self';
            media.name = file.filename;
            media.length = file.length;
            return media;
        },
        onChange: function(item){
            if(this.get("chooser")){
                this.get("chooser").trigger("change", item);
            }
        },
        setup: function() {
            this.on("change", this.onChange);

            var $btn = this.$('[data-role=uploader-btn]');
            var progressbar = new UploadProgressBar({
                element: $btn.data('progressbar')
            });
            this.set('uploaderProgressbar', progressbar);
            this.set('uploader', this._createUpload($btn, progressbar));
        },

        _createUpload: function($btn, progressbar) {
            var self = this;

            var settings = $.extend({}, {
                file_types : "*.*",
                file_size_limit : "10 MB",
                file_upload_limit : 1,
                file_queue_limit: 1,
                file_post_name: 'file',

                button_placeholder_id : $btn.attr('id'),
                button_width: "75",
                button_height: "35",
                button_text: "<span class=\"btnText\">上传</span>",
                button_text_style : ".btnText { color: #333; font-size:16px;}",
                button_text_left_padding : 18,
                button_text_top_padding : 5,
                button_image_url: $btn.data('buttonImage'),
                button_window_mode: 'transparent',

                file_dialog_complete_handler: function(numFilesSelected, numFilesQueued) {
                    if (numFilesSelected == 0) {
                        return;
                    }
                    if (numFilesSelected > 1) {
                        Notify.danger('一次只能上传一个文件，请重新选择。');
                        return ;
                    }

                    if (numFilesQueued == 0) {
                        Notify.info('文件正在上传中，请等待本次上传完毕后，再上传。');
                        return ;
                    }
                    this.startUpload();
                },

                upload_start_handler: function(file) {
                    if(self.get("chooser")){
                        self.get("chooser").trigger("preUpload", file);
                    }else if(self.get("preUpload")){
                        self.get("preUpload").call(self,this,file);
                    }
                    progressbar.reset().show();
                },

                upload_progress_handler: function(file, bytesLoaded, bytesTotal) {
                    var percentage = Math.ceil((bytesLoaded / bytesTotal) * 100);
                    progressbar.setProgress(percentage);
                },

                upload_error_handler: function(file, errorCode, message) {
                    Notify.danger('文件上传失败，请重试！');
                },

                upload_success_handler: function(file, serverData) {
                    progressbar.setComplete().hide();
                    serverData = $.parseJSON(serverData);

                    if ($btn.data('callback')) {
                        $.post($btn.data('callback'), serverData, function(response) {
                            var media = self._convertFileToMedia(response);
                            self.trigger('change',  media);
                            Notify.success('文件上传成功！');
                        }, 'json');
                    } else {
                        var media = self._convertFileToMedia(serverData);
                        self.trigger('change',  media);
                        Notify.success('文件上传成功！');
                    }


                }
            }, this.get('uploaderSettings'));

            if ($btn.data('filetypes')) {
                settings.file_types = $btn.data('filetypes');
            }
            this.set("uploaderSettings", settings);
            if(this._supportChunkUpload() && $btn.data('storageType')=="cloud"){
                settings.element=this.element;
                settings.progressbar = progressbar;
                return new ChunkUpload(settings);
            }else{
                return new SWFUpload(settings);
            }
        },
        
        _supportChunkUpload: function(){
            if(this.get("uploaderSettings").file_types.indexOf("ppt")>-1 || typeof(FileReader)=="undefined" || typeof(XMLHttpRequest)=="undefined"){
                return false;
            }
            return true;
        },

        destroy: function(){
            if(this._supportChunkUpload() && this.$('[data-role=uploader-btn]').data('storageType')=="cloud"){
                var uploader = this.get("uploader");
                uploader.destroy();
            }
        }

    });

    module.exports = UploadPanel;
});
