
class PktCityIP {
    constructor(ip, time) {
        this.ip = ip;
        this.time = Date.parse(time);
        this.mesh = undefined;
    }

    get x() {
        return this.get_x();
    }

    get_x() {
        return this.mesh.position.x;
    }

    get z() {
        return this.get_z();
    }

    get_z() {
        return this.mesh.position.z;
    }
}

function PktCityCreateMesh(pktip, x, z, material, scene, time) {
    /* FIXME regle de trois sur le temps */
    var height = (time - pktip.time)/(1000 * 500);
    pktip.mesh = BABYLON.Mesh.CreateCylinder("cylinder", height, 1, 1, 16, 1, scene);
    pktip.mesh.position.x = x;
    pktip.mesh.position.z = z;
    pktip.mesh.position.y = height / 2;
    /* TODO set time */
    pktip.mesh.material = material;
return;
}

function PktCityCreateAlert(SceneIPs, item, etime, material, matsource, mattarget, scene, time, starttime, HUD) {
    var y = (time - etime)/(1000 * 500);
    var source = SceneIPs[item['alert']['source']['ip']];
    var target = SceneIPs[item['alert']['target']['ip']];

    //console.log("x " + source.mesh.position.x + " y " + source.y);
    var curve = [ new BABYLON.Vector3(source.x, y, source.z), new BABYLON.Vector3(target.x, y, target.z)];
    var tube = BABYLON.Mesh.CreateTube("tube", curve, 0.1, 60, null, 0, scene, false, BABYLON.Mesh.FRONTSIDE);
    tube.material = material;  
    var attack = BABYLON.Mesh.CreateSphere("attack", 16, 0.2, scene);
    var sph_source = BABYLON.Mesh.CreateSphere("source", 16, 1.1, scene);
    sph_source.position.x = source.x;
    sph_source.position.y = y;
    sph_source.position.z = source.z;
    sph_source.material = matsource.clone("source " + y);

    sph_source.actionManager = new BABYLON.ActionManager(scene);
    sph_source.actionManager.registerAction(new BABYLON.ExecuteCodeAction(BABYLON.ActionManager.OnPointerOverTrigger, function(ev){
				    var meshLocal = ev.meshUnderPointer
				    meshLocal.material.alpha = 0.1;
                                    var hudsource = HUD.getChildByName("HUDsource");
                                    hudsource.text = source.ip;
                                    var hudtarget = HUD.getChildByName("HUDtarget");
                                    hudtarget.text = target.ip;
				    //canvas.style.cursor = "move"
				    sph_target.material.alpha = 0.1;
				    }, false));
    sph_source.actionManager.registerAction(new BABYLON.ExecuteCodeAction(BABYLON.ActionManager.OnPointerOutTrigger, function(ev){
			    var meshLocal = ev.meshUnderPointer
			    meshLocal.material.alpha = 1;
			    //canvas.style.cursor = "default" ;
                            var hudvalue = HUD.getChildByName("HUDsource");
                            hudvalue.text = "";
                            hudvalue = HUD.getChildByName("HUDtarget");
                            hudvalue.text = "";
                            sph_target.material.alpha = 1;
			    },false));

    var sph_target = BABYLON.Mesh.CreateSphere("target", 16, 1.1, scene);
    sph_target.position.x = target.x;
    sph_target.position.y = y;
    sph_target.position.z = target.z;
    sph_target.material = mattarget.clone("target " + y);

    var duration = time - starttime;
    var fps = 30;
    var nbframes = fps * 10;
    var animation = new BABYLON.Animation("attackAnimation", "position", fps, BABYLON.Animation.ANIMATIONTYPE_VECTOR3, BABYLON.Animation.ANIMATIONLOOPMODE_CYCLE);
    var keys = [];
    startframe = (etime-starttime)/(time-starttime)*nbframes;
    endframe = startframe + 50;
    keys.push({frame: startframe, value:   new BABYLON.Vector3(source.x, y, source.z)});
    keys.push({frame: endframe, value:   new BABYLON.Vector3(target.x, y, target.z)});
    keys.push({frame: endframe + 1, value:   new BABYLON.Vector3(source.x, y, source.z)});
    keys.push({frame: nbframes, value:   new BABYLON.Vector3(source.x, y, source.z)});
    animation.setKeys(keys);
    attack.animations = [];
    attack.animations.push(animation);
    scene.beginAnimation(attack, 0, nbframes, true);
}
/*
class PktCityAlert {
    constructor(jdata) {
        this.source = PktCityIPjdata['alert']['source']['ip'];
        this.target = jdata['alert']['target']['ip'];
        this.time = date.Parse();
    }
}
*/

function PktCityCreateScene(data) {

        // Get the data
        var SceneIPs = {};

        var starttime = undefined;
        var time = undefined;
        data.forEach(function(es_item, index, array) {
            item  = es_item['_source'];
            if (!(item['alert']['source']['ip'] in SceneIPs)) {
                var evip = new PktCityIP(item['alert']['source']['ip'], item['timestamp']);
                SceneIPs[item['alert']['source']['ip']] = evip;
            }
            if (!(item['alert']['target']['ip'] in SceneIPs)) {
                var evip = new PktCityIP(item['alert']['target']['ip'], item['timestamp']);
                SceneIPs[item['alert']['target']['ip']] = evip;
            }
            etime = Date.parse(item['timestamp']);
            if ((starttime == undefined) || (etime < starttime)) {
                starttime = etime;
            }
            if ((time == undefined) || (etime > time)) {
                time = etime;
            }
        });
        console.log(Object.keys(SceneIPs).length);
        // Get the canvas element from our HTML below
        var canvas = document.querySelector("#renderCanvas");
        // Load the BABYLON 3D engine
        var engine = new BABYLON.Engine(canvas, true);
        // -------------------------------------------------------------
        // Here begins a function that we will 'call' just after it's built
        var createScene = function() {
                // Now create a basic Babylon Scene object
                var scene = new BABYLON.Scene(engine);
                // Change the scene background color to green.
                scene.clearColor = new BABYLON.Color3(0, 1, 0);
                // This creates and positions a free camera
                var camera = new BABYLON.FreeCamera("camera1", new BABYLON.Vector3(5, 20, -15), scene);
                // This targets the camera to scene origin
                camera.setTarget(new BABYLON.Vector3(15, 10, 15));
                // This attaches the camera to the canvas
                camera.attachControl(canvas, false);
                // This creates a light, aiming 0,1,0 - to the sky.
                var light = new BABYLON.HemisphericLight("light1", new BABYLON.Vector3(0, 1, 0), scene);
                // Dim the light a small amount
                light.intensity = .5;
                var materialCylinder = new BABYLON.StandardMaterial("texture1", scene);
                materialCylinder.alpha = 1;
                var mod = Math.ceil(Math.sqrt(Object.keys(SceneIPs).length));
                /* FIXME we need to sort them by IP value */
                var sorted = [];
                for (var key in SceneIPs) {
                    sorted.push(key);
                }
                function ip2int(ip) {
                        return ip.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
                }
                sorted.sort(function(a, b){ return ip2int(a) - ip2int(b)});
                for (i = 0; i < sorted.length; i++) {
                    var x = Math.floor(i / mod);
                    var z = i % mod;
                    /* scale value */
                    x = x * 30 / mod;
                    z = z * 30 / mod;
                    /* translate mesh by network */
                    if (SceneIPs[sorted[i]].ip.startsWith("192")) {
                        x = x + 0;
                        z = z + 0;
                    } else if (SceneIPs[sorted[i]].ip.startsWith("10.")) {
                        x = x + 30;
                        z = z - 30;
                    } else {
                        x = 2 * x - 30;
                        z = 2 * z - 15;
                    }
                    PktCityCreateMesh(SceneIPs[sorted[i]], x, z, materialCylinder, scene, time);
                    console.log(SceneIPs[sorted[i]].x);
                }

                // a tube
                var matTube = new BABYLON.StandardMaterial("mat1", scene);
                matTube.alpha = 0.1;
                matTube.diffuseColor = new BABYLON.Color3(0.5, 0.5, 1.0);
                matTube.backFaceCulling = false;
                matTube.wireframe = false;

                var matSource = new BABYLON.StandardMaterial("source", scene);
                matSource.difffuseColor = new BABYLON.Color3(1.0, 0.2, 0.2);
                matSource.emissiveColor = new BABYLON.Color3(1, 0, 0);
                var matTarget = new BABYLON.StandardMaterial("target", scene);
                matTarget.difffuseColor = new BABYLON.Color3(0.2, 1, 0.2);
                matTarget.emissiveColor = new BABYLON.Color3(0, 0, 1);

		var HUD = new BABYLON.GUI.AdvancedDynamicTexture.CreateFullscreenUI("PktcityHUD");
                var HUDrectinfo = new BABYLON.GUI.Rectangle("Rectinfo");
                //HUDrectinfo.background =  new BABYLON.Color3(0.3, 0.3, 0.3);
                HUDrectinfo.top = window.innerHeight / 2 - 200;
                HUDrectinfo.left = window.innerWidth / 2 - 160;
                HUDrectinfo.width = "" + 250 + "px";
                HUDrectinfo.height = "" + 60 + "px";
                HUDrectinfo.thickness = 2;
                HUDrectinfo.cornerRadius = 10;
                HUD.addControl(HUDrectinfo);
                var HUDpanelH = new BABYLON.GUI.StackPanel();
                HUDpanelH.isVertical = false;
                HUDrectinfo.addControl(HUDpanelH);
                var HUDlabel = new BABYLON.GUI.StackPanel();
                HUDpanelH.addControl(HUDlabel);
                var HUDvalue = new BABYLON.GUI.StackPanel();
                HUDpanelH.addControl(HUDvalue);
                var info_height= "20px";
                var HUDlabelsource = new BABYLON.GUI.TextBlock("HUDlabelsource");
                HUDlabelsource.text = "Source";
                HUDlabelsource.color = "white";
                HUDlabelsource.fontSize = 16;
                HUDlabelsource.width = "125px";
                HUDlabelsource.height = info_height;
                HUDlabel.addControl(HUDlabelsource);
                var HUDlabeltarget = new BABYLON.GUI.TextBlock("HUDlabeltarget");
                HUDlabeltarget.text = "Target";
                HUDlabeltarget.color = "white";
                HUDlabeltarget.fontSize = 16;
                HUDlabeltarget.width = "125px";
                HUDlabeltarget.height = info_height;
                HUDlabel.addControl(HUDlabeltarget);

                var HUDsource = new BABYLON.GUI.TextBlock("HUDsource");
                HUDsource.color = "white";
                HUDsource.fontSize = 16;
                HUDsource.width = "" + 125 + "px";
                HUDsource.height = info_height;
                HUDvalue.addControl(HUDsource);

                var HUDtarget = new BABYLON.GUI.TextBlock("HUDtarget");
                HUDtarget.color = "white";
                HUDtarget.fontSize = 16;
                HUDtarget.width = "" + 125 + "px";
                HUDtarget.height = info_height;
                HUDvalue.addControl(HUDtarget);

                data.forEach(function(es_item, index, array) {
                    item  = es_item['_source'];
                    PktCityCreateAlert(SceneIPs, item,
                        Date.parse(item['timestamp']),
                        matTube,
                        matSource,
                        matTarget,
                        scene,
                        time, starttime, HUDvalue);
                });

                // Let's try our built-in 'ground' shape. Params: name, width, depth, subdivisions, scene
                var materialGround = new BABYLON.StandardMaterial("texture1", scene);
                materialGround.alpha = 1;
                var ground = BABYLON.Mesh.CreateGround("ground1", 1000, 1000, 2, scene);
                ground.material = materialGround;
                // Leave this function
                var skybox = BABYLON.Mesh.CreateBox("skyBox", 300.0, scene);
                var skyboxMaterial = new BABYLON.StandardMaterial("skyBox", scene);
                skyboxMaterial.reflectionTexture = new BABYLON.CubeTexture("textures/skybox/skybox", scene);
                skyboxMaterial.reflectionTexture.coordinatesMode = BABYLON.Texture.SKYBOX_MODE;
                skyboxMaterial.backFaceCulling = false;
                skyboxMaterial.disableLighting = true;
                skybox.material = skyboxMaterial;	
                skybox.infiniteDistance = true;
                skyboxMaterial.disableLighting = true;

                return scene;
        }; // End of createScene function

        // -------------------------------------------------------------
        // Now, call the createScene function that you just finished creating
        var scene = createScene();
        // Register a render loop to repeatedly render the scene
        engine.runRenderLoop(function () {
                        scene.render();
                        });
        // Watch for browser/canvas resize events
        window.addEventListener("resize", function () {
                        engine.resize();
                        //HUDinfo.top = window.innerHeight / 2 - 200;
                        //HUDinfo.left = window.innerWidth / 2 - 160;
                        });


}
